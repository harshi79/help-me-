#!/usr/bin/env python3
#     One command, whole pipeline.
#
#         python3 run.py yourfile.exe
#
#     Produces a folder called 'recovered/' containing everything the binary
#     gives up, plus a plain-English summary at the top of report.txt.

from __future__ import annotations

import argparse
import importlib.util
import marshal
import os
import re
import struct
import subprocess
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import nuitka_forensics as nf  # noqa: E402
import reconstruct as rc  # noqa: E402


# ---------------------------------------------------------------------------
# Which Python built this binary?
# ---------------------------------------------------------------------------
#
# Required to stamp recovered .pyc files with the right magic number, so that
# decompilers interpret the bytecode correctly.

# Little-endian uint32 of the four magic bytes.  3.11 is b"A7 0D 0D 0A".
PYC_MAGIC = {
    (3, 7): 0x0A0D0D42,
    (3, 8): 0x0A0D0D55,
    (3, 9): 0x0A0D0D61,
    (3, 10): 0x0A0D0D6F,
    (3, 11): 0x0A0D0DA7,
    (3, 12): 0x0A0D0DCB,
    (3, 13): 0x0A0D0DF3,
}


def detect_python_version(data, target=None):
    """Infer the build-time Python version from strings in the binary.

    For a onefile build the interesting bytes are inside the compressed
    payload, so decompress and scan that too.
    """
    if target:
        try:
            blobs, meta = nf.load_blobs(target)
            if meta.get("packaging") == "onefile":
                of = nf.find_onefile_payload(open(target, "rb").read())
                if of:
                    files, _ = nf.parse_onefile_payload(of[2], of[0])
                    for name, blob in (files or {}).items():
                        if blob and blob[:2] in (b"MZ", b"\x7fE"):
                            v = detect_python_version(blob, target=None)
                            if v:
                                return v
        except Exception:
            pass

    pats = [
        (rb"python(\d)(\d{1,2})\.dll", 1, 2),
        (rb"python(\d)\.(\d{1,2})\b", 1, 2),
        (rb"Python (\d)\.(\d{1,2})\.\d+", 1, 2),
        (rb"libpython(\d)\.(\d{1,2})", 1, 2),
    ]
    votes = {}
    for pat, gi, gj in pats:
        for m in re.finditer(pat, data):
            key = (int(m.group(gi)), int(m.group(gj)))
            if key in PYC_MAGIC:
                votes[key] = votes.get(key, 0) + 1
    if not votes:
        return None
    return max(votes.items(), key=lambda kv: kv[1])[0]


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_strings(detail, path):
    if not detail:
        return 0
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        for s in sorted(detail["strings"]):
            f.write("%r\n" % s)
    return len(detail["strings"])


def write_bytecode(detail, outdir, magic, on_error=None):
    """Write recovered demoted-module bytecode as .pyc files.

    `magic` may be an int or the 4-byte form from importlib.util.MAGIC_NUMBER.
    """
    os.makedirs(outdir, exist_ok=True)
    written = []
    if not detail:
        return written

    if isinstance(magic, (bytes, bytearray)):
        magic_int = struct.unpack("<I", bytes(magic))[0]
    else:
        magic_int = int(magic)

    for entry in detail["bytecode"]:
        if not entry.get("recovered"):
            continue
        code = entry["code"]
        name = entry.get("co_filename") or "module"
        safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
        if safe.endswith(".py"):
            safe = safe[:-3]

        path = os.path.join(outdir, safe + ".pyc")
        # Collisions: several modules can share a basename (__init__.py).
        n = 1
        while os.path.exists(path):
            path = os.path.join(
                outdir, safe + ("_%d" % n) + ".pyc")
            n += 1
        try:
            with open(path, "wb") as f:
                f.write(struct.pack("<I", magic_int))
                f.write(struct.pack("<I", 0))   # flags
                f.write(struct.pack("<I", 0))   # mtime
                f.write(struct.pack("<I", 0))   # source size
                f.write(marshal.dumps(code))
        except Exception as exc:
            if on_error:
                on_error("%s: %s" % (name, exc))
            continue
        written.append((path, name))

    return written


def try_decompile(pyc_files, outdir):
    """If pycdc is on PATH, decompile the recovered .pyc files."""
    exe = None
    for cand in ("pycdc", "pycdc.exe"):
        for d in os.environ.get("PATH", "").split(os.pathsep):
            p = os.path.join(d, cand)
            if os.path.isfile(p) and os.access(p, os.X_OK):
                exe = p
                break
        if exe:
            break

    if exe is None:
        return None, "pycdc not found on PATH - skipping decompilation"

    os.makedirs(outdir, exist_ok=True)
    done = []
    for path, orig in pyc_files:
        try:
            res = subprocess.run([exe, path], capture_output=True, timeout=120)
        except Exception:
            continue
        text = res.stdout.decode("utf-8", "replace")
        if not text.strip():
            continue
        target = os.path.join(
            outdir, os.path.basename(path).replace(".pyc", ".py"))
        with open(target, "w", encoding="utf-8") as f:
            f.write(text)
        done.append((target, orig))
    return done, None


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Recover everything a Nuitka binary gives up.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 run.py myapp.exe
  python3 run.py myapp.exe -o my_results
""")
    ap.add_argument("target", help="the .exe / binary to analyse")
    ap.add_argument("-o", "--outdir", default="recovered",
                    help="output folder (default: recovered)")
    args = ap.parse_args(argv)

    target = args.target
    out = args.outdir

    if not os.path.isfile(target):
        print("ERROR: no such file: %s" % target)
        return 2

    if not nf is None and importlib.util.find_spec is None:  # pragma: no cover
        pass

    size_mb = os.path.getsize(target) / 1048576.0
    print("=" * 66)
    print("Nuitka recovery - %s (%.1f MB)" % (os.path.basename(target), size_mb))
    print("=" * 66)

    os.makedirs(out, exist_ok=True)

    # --- stage 1: what is in the file ---------------------------------
    print("\n[1/5] Reading the binary and locating the constants blob ...")
    report, detail = nf.analyse(target)

    if not report["blob"].get("found"):
        print("\nNo Nuitka constants blob found.")
        of = report.get("onefile")
        if of:
            print("A onefile payload WAS detected but could not be unpacked:")
            print("   %s" % of.get("error", "unknown error"))
            if "zstandard" in (of.get("error") or ""):
                print("\nFix:  pip install zstandard")
        else:
            print("The file is either not a Nuitka build, or is encrypted by")
            print("a third-party protector.")
        return 1

    if report["blob"].get("offset") is not None:
        print("      constants blob at offset 0x%X"
              % report["blob"]["offset"])

    blobs, meta = nf.load_blobs(target)
    if meta.get("packaging") == "onefile":
        print("      onefile build: unpacked payload, inner binary = %s"
              % meta.get("onefile_inner", "?"))

    n_modules = sum(1 for b in blobs if b.name and not b.name.startswith("."))
    print("      %d constants across %d blobs, %d module(s)"
          % (report["blob"]["total_constants"], len(blobs), n_modules))

    # --- stage 2: full report -----------------------------------------
    print("\n[2/5] Writing full technical report ...")
    with open(os.path.join(out, "report.txt"), "w", encoding="utf-8") as f:
        f.write(nf.render(report, detail, show_strings=False))
    n_strings = write_strings(detail, os.path.join(out, "strings.txt"))
    print("      report.txt + strings.txt (%d string literals)" % n_strings)

    # --- stage 3: reconstruction evidence -----------------------------
    print("\n[3/5] Extracting per-function evidence ...")
    modules, _ = rc.extract_evidence(target)
    real_mods = [m for m in (modules or {})
                 if m and not m.startswith("<") and not m.startswith(".")]
    n_funcs = sum(len(modules[m]["functions"]) for m in (modules or {}))

    if modules:
        with open(os.path.join(out, "evidence.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(rc.render_module_card(m, i)
                              for m, i in modules.items()))
        with open(os.path.join(out, "prompt.txt"), "w", encoding="utf-8") as f:
            f.write(rc.render_prompt(modules, os.path.basename(target)))
        rc.write_skeleton(modules, os.path.join(out, "skeleton"))
        print("      evidence.txt, prompt.txt, skeleton/ "
              "(%d modules, %d functions)" % (len(real_mods), n_funcs))
    else:
        print("      no functions recoverable")

    # --- stage 4: bytecode --------------------------------------------
    print("\n[4/5] Recovering embedded bytecode ...")
    data = open(target, "rb").read()
    pyver = detect_python_version(data, target=target)
    if pyver and pyver in PYC_MAGIC:
        magic = PYC_MAGIC[pyver]
        print("      build Python detected: %d.%d" % pyver)
    else:
        magic = importlib.util.MAGIC_NUMBER
        print("      build Python not detected; assuming this machine's version")

    _errs = []
    pycs = write_bytecode(
        detail, os.path.join(out, "bytecode"), magic,
        on_error=_errs.append)
    for msg in _errs[:3]:
        print("      write failed: %s" % msg)
    if _errs:
        print("      %d of %d writes failed"
              % (len(_errs), len(_errs) + len(pycs)))
    if pycs:
        print("      %d modules had bytecode embedded (these are lossless)"
              % len(pycs))
    else:
        print("      none - every module was compiled to native code, so no")
        print("      bytecode exists in this file")

    # --- stage 5: decompile -------------------------------------------
    if pycs:
        print("\n[5/5] Decompiling recovered bytecode ...")
        done, err = try_decompile(pycs, os.path.join(out, "decompiled"))
        if err:
            print("      %s" % err)
        else:
            print("      %d files decompiled -> decompiled/" % len(done))
    else:
        print("\n[5/5] Skipped (nothing to decompile)")

    # --- summary -------------------------------------------------------
    with open(os.path.join(out, "START_HERE.txt"), "w", encoding="utf-8") as f:
        w = f.write
        w("RECOVERY SUMMARY\n")
        w("=" * 60 + "\n\n")
        w("Target : %s\n" % os.path.abspath(target))
        w("Size   : %.1f MB\n" % size_mb)
        if meta.get("packaging") == "onefile":
            w("Packaging: ONE-FILE (self-extracting). Payload was unpacked.\n")
        w("\n")
        w("WHAT IS IN THIS FOLDER\n")
        w("-" * 60 + "\n")
        w("START_HERE.txt    this file\n")
        w("report.txt        technical report: modules, symbols, paths\n")
        w("strings.txt       every string literal in the program (%d)\n" % n_strings)
        w("evidence.txt      per-function evidence for reconstruction\n")
        w("prompt.txt        paste into an LLM to rebuild the bodies\n")
        w("skeleton/         exact module tree with true signatures\n")
        if pycs:
            w("bytecode/         %d recovered .pyc files (LOSSLESS)\n" % len(pycs))
            w("decompiled/       readable source for those modules\n")
        w("\n")
        w("HOW MUCH WAS RECOVERED\n")
        w("-" * 60 + "\n")
        w("Modules identified      : %d\n" % len(real_mods))
        w("Functions recovered     : %d\n" % n_funcs)
        w("String literals         : %d\n" % n_strings)
        w("Code objects with exact\n"
          "  name/signature/line   : %d\n" % report.get("total_code_objects", 0))
        w("Modules with lossless\n"
          "  bytecode recovered    : %d\n" % len(pycs))
        w("\n")
        w("WHAT WAS NOT RECOVERED\n")
        w("-" * 60 + "\n")
        if pycs:
            w("For the %d modules WITH bytecode above: everything, decompile them.\n"
              % len(pycs))
        w("For all other modules:\n")
        w("  - function bodies (they were compiled to machine code)\n")
        w("  - comments and formatting (never survive compilation)\n")
        w("  - builtin names like len/sum/range (compiled to direct C calls)\n")
        w("\n")
        w("NEXT STEP\n")
        w("-" * 60 + "\n")
        w("Open prompt.txt, paste it into an LLM, and ask it to write the\n")
        w("modules. It contains every fact recovered from the binary. Treat\n")
        w("its output as a close approximation, not the original source:\n")
        w("test it before trusting it.\n")

    print("\n" + "=" * 66)
    print("DONE -> %s/" % out)
    print("=" * 66)
    print("  Modules identified   : %d" % len(real_mods))
    print("  Functions recovered  : %d" % n_funcs)
    print("  String literals      : %d" % n_strings)
    print("  Lossless bytecode    : %d module(s)" % len(pycs))
    print()
    print("  Start with: %s/START_HERE.txt" % out)
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
