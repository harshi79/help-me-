#!/usr/bin/env python3
"""Assemble nuitka-forensics/decompile.py as one self-contained file.

The decoder in nuitka_forensics.py is heavily tested against ground truth, so
rather than retyping it (and risking new bugs) this generator splices the tested
bodies together and appends the GUI.  The result is verified afterwards by
running its CLI mode against known-good specimens and comparing output.
"""

import os
import re

HERE = "/home/user/help-me-/nuitka-forensics"
OUT = "/home/user/help-me-/decompile.py"

# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------

HEADER = '''#!/usr/bin/env python3
#     decompile.py - one-file Nuitka recovery tool.
#
#     A single self-contained script: load a Nuitka-built executable, watch the
#     log, get the results in a folder.  No install, no extra files.
#
#         python3 decompile.py            -> opens the GUI
#         python3 decompile.py app.exe    -> command-line mode (no GUI needed)
#
#     WHAT IT DOES
#       Nuitka compiles Python to C and then to machine code.  It does not
#       obfuscate, and it leaves a "constants blob" in the binary that holds
#       real information: every string literal, every module name, the original
#       source file paths, and for every function its name, exact parameter
#       list, every local variable name, and the line number it was defined on.
#
#       This tool decodes that blob.  It also recovers genuine CPython bytecode
#       for any module Nuitka left uncompiled ("demoted"), which can be
#       decompiled back to readable source.
#
#     WHAT IT CANNOT DO
#       Function bodies of normally compiled modules are machine code and are
#       not in the file in any recoverable form.  Comments and formatting never
#       survive any compiler.  The skeleton and evidence this produces is a
#       faithful map, not the original source - never ship a reconstruction
#       without testing it.
#
#     Runs on Python 3.8+.  The GUI needs tkinter (bundled with the standard
#     Windows and macOS installers).  If tkinter is missing, command-line mode
#     is used automatically.

from __future__ import annotations

import argparse
import io
import json
import marshal
import os
import pickle
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
import types
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))

'''

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

GUI = r'''

# ===========================================================================
# ENGINE
# ===========================================================================


def _human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.1f %s" % (n, unit)
        n /= 1024.0


def detect_python_version(data, target=None):
    """Infer the build-time Python version, looking inside a onefile payload."""
    if target:
        try:
            payload = find_onefile_payload(open(target, "rb").read())
            if payload:
                files, _ = parse_onefile_payload(payload[2], payload[0])
                for _name, blob in (files or {}).items():
                    if blob and blob[:2] in (b"MZ", b"\x7fE"):
                        v = detect_python_version(blob)
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


# Little-endian uint32 of the four .pyc magic bytes.  3.11 is b"A7 0D 0D 0A".
PYC_MAGIC = {
    (3, 7): 0x0A0D0D42,
    (3, 8): 0x0A0D0D55,
    (3, 9): 0x0A0D0D61,
    (3, 10): 0x0A0D0D6F,
    (3, 11): 0x0A0D0DA7,
    (3, 12): 0x0A0D0DCB,
    (3, 13): 0x0A0D0DF3,
}


class Engine(object):
    """Runs the full recovery pipeline, reporting progress through a callback.

    `log(message, level)` is called from a worker thread; level is one of
    "info", "ok", "warn", "err", "head".
    """

    def __init__(self, log=None):
        self.log = log or (lambda m, l="info": None)
        self.stats = {}

    def _l(self, msg, level="info"):
        self.log(msg, level)

    def run(self, target, outdir):
        t0 = time.time()

        if not os.path.isfile(target):
            self._l("No such file: %s" % target, "err")
            return 1

        size = os.path.getsize(target)
        self._l("File: %s" % os.path.basename(target), "head")
        self._l("Size: %s" % _human(size))
        self._l("")

        if os.path.exists(outdir):
            try:
                shutil.rmtree(outdir)
            except Exception as exc:
                self._l("Could not clear old results folder: %s" % exc, "warn")
        os.makedirs(outdir, exist_ok=True)

        # ---- 1. locate the blob ---------------------------------------
        self._l("[1/5] Scanning the binary ...")
        try:
            report, detail = analyse(target)
        except Exception as exc:
            self._l("Analysis failed: %s" % exc, "err")
            return 1

        if not report["blob"].get("found"):
            self._l("")
            self._l("No Nuitka constants blob found.", "err")
            of = report.get("onefile")
            if of:
                self._l("A one-file payload was detected but could not be unpacked:")
                self._l("   %s" % of.get("error", "unknown error"), "warn")
                if "zstandard" in (of.get("error") or ""):
                    self._l("")
                    self._l("Fix:  pip install zstandard", "warn")
            else:
                self._l("The file is either not a Nuitka build, or it is")
                self._l("encrypted by a third-party protector.")
            return 1

        blobs, meta = load_blobs(target)
        if meta.get("packaging") == "onefile":
            self._l("One-file build: unpacked the payload.", "ok")
            self._l("   inner binary: %s" % meta.get("onefile_inner", "?"))
            self._l("   files inside: %s" % meta.get("onefile_files", "?"))

        self._l("Constants blob found at offset 0x%X" % report["blob"]["offset"], "ok")
        self._l("%d constants, %d bytes, %d module(s)"
                % (report["blob"]["total_constants"],
                   report["blob"]["blob_size_total"],
                   len(blobs)))
        self._l("")

        # ---- 2. technical report --------------------------------------
        self._l("[2/5] Writing technical report ...")
        with open(os.path.join(outdir, "report.txt"), "w", encoding="utf-8") as f:
            f.write(render(report, detail, show_strings=False))

        n_strings = 0
        if detail:
            with open(os.path.join(outdir, "strings.txt"), "w",
                      encoding="utf-8", errors="replace") as f:
                for s in sorted(detail["strings"]):
                    f.write("%r\n" % s)
            n_strings = len(detail["strings"])
        self._l("   report.txt", "ok")
        self._l("   strings.txt - %d string literals" % n_strings, "ok")
        self._l("")

        # ---- 3. reconstruction evidence -------------------------------
        self._l("[3/5] Extracting function evidence ...")
        modules, _ = extract_evidence(target)
        real = [m for m in (modules or {})
                if m and not m.startswith("<") and not m.startswith(".")]
        n_funcs = sum(len(modules[m]["functions"]) for m in (modules or {}))

        if modules:
            with open(os.path.join(outdir, "evidence.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(render_module_card(m, i)
                                  for m, i in modules.items()))
            with open(os.path.join(outdir, "prompt.txt"), "w", encoding="utf-8") as f:
                f.write(render_prompt(modules, os.path.basename(target)))
            write_skeleton(modules, os.path.join(outdir, "skeleton"))
            self._l("   evidence.txt", "ok")
            self._l("   prompt.txt  (paste into an LLM to rebuild bodies)", "ok")
            self._l("   skeleton/   - %d modules, %d functions" % (len(real), n_funcs), "ok")
        else:
            self._l("   no functions recoverable", "warn")
        self._l("")

        # ---- 4. bytecode ----------------------------------------------
        self._l("[4/5] Recovering embedded bytecode ...")
        data = open(target, "rb").read()
        pyver = detect_python_version(data, target=target)
        if pyver and pyver in PYC_MAGIC:
            magic = PYC_MAGIC[pyver]
            self._l("   built with Python %d.%d" % pyver)
        else:
            magic = current_pyc_magic()
            self._l("   build Python not detected; assuming %d.%d"
                    % (sys.version_info[0], sys.version_info[1]))

        pycs = self._write_bytecode(detail, os.path.join(outdir, "bytecode"), magic)
        if pycs:
            self._l("   %d modules had bytecode embedded (LOSSLESS)" % len(pycs), "ok")
        else:
            self._l("   none - every module was compiled to native code, so no")
            self._l("   bytecode exists in this file")
        self._l("")

        # ---- 5. decompile ---------------------------------------------
        n_decomp = 0
        if pycs:
            self._l("[5/5] Decompiling recovered bytecode ...")
            n_decomp, err = self._decompile(pycs, os.path.join(outdir, "decompiled"))
            if err:
                self._l("   %s" % err, "warn")
                self._l("   The .pyc files in bytecode/ are still valid.")
            else:
                self._l("   %d files decompiled to readable source" % n_decomp, "ok")
        else:
            self._l("[5/5] Skipped (nothing to decompile)")
        self._l("")

        # ---- summary ---------------------------------------------------
        self.stats = {
            "modules": len(real),
            "functions": n_funcs,
            "strings": n_strings,
            "bytecode": len(pycs),
            "decompiled": n_decomp,
            "seconds": time.time() - t0,
        }

        self._write_summary(os.path.join(outdir, "START_HERE.txt"), target,
                            size, meta, report, real, n_funcs, n_strings,
                            pycs, n_decomp)

        self._l("Done in %.1f seconds." % self.stats["seconds"], "head")
        self._l("")
        self._l("   modules identified : %d" % len(real), "ok")
        self._l("   functions recovered: %d" % n_funcs, "ok")
        self._l("   string literals    : %d" % n_strings, "ok")
        self._l("   lossless bytecode  : %d module(s)" % len(pycs), "ok")
        self._l("   decompiled to source: %d file(s)" % n_decomp, "ok")
        self._l("")
        self._l("Results saved to: %s" % outdir, "head")
        return 0

    # -- helpers ---------------------------------------------------------

    def _write_bytecode(self, detail, outdir, magic):
        os.makedirs(outdir, exist_ok=True)
        written = []
        if not detail:
            return written

        if isinstance(magic, (bytes, bytearray)):
            magic = struct.unpack("<I", bytes(magic))[0]

        for entry in detail["bytecode"]:
            if not entry.get("recovered"):
                continue
            code = entry["code"]
            name = entry.get("co_filename") or "module"
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
            if safe.endswith(".py"):
                safe = safe[:-3]

            path = os.path.join(outdir, safe + ".pyc")
            n = 1
            while os.path.exists(path):
                path = os.path.join(outdir, "%s_%d.pyc" % (safe, n))
                n += 1
            try:
                with open(path, "wb") as f:
                    f.write(struct.pack("<I", magic))
                    f.write(struct.pack("<I", 0))
                    f.write(struct.pack("<I", 0))
                    f.write(struct.pack("<I", 0))
                    f.write(marshal.dumps(code))
            except Exception as exc:
                self._l("   could not write %s: %s" % (name, exc), "warn")
                continue
            written.append((path, name))
        return written

    def _decompile(self, pyc_files, outdir):
        exe = shutil.which("pycdc") or shutil.which("pycdc.exe")
        if not exe:
            return 0, ("pycdc not found on PATH - skipping. Install it with:\n"
                       "   git clone https://github.com/zrax/pycdc\n"
                       "   (build it, then put pycdc on your PATH)")
        os.makedirs(outdir, exist_ok=True)
        done = 0
        for path, _orig in pyc_files:
            try:
                res = subprocess.run([exe, path], capture_output=True, timeout=120)
            except Exception:
                continue
            text = res.stdout.decode("utf-8", "replace")
            if not text.strip():
                continue
            target = os.path.join(outdir,
                                  os.path.basename(path).replace(".pyc", ".py"))
            with open(target, "w", encoding="utf-8") as f:
                f.write(text)
            done += 1
        return done, None

    def _write_summary(self, path, target, size, meta, report, real, n_funcs,
                       n_strings, pycs, n_decomp):
        with open(path, "w", encoding="utf-8") as f:
            w = f.write
            w("RECOVERY SUMMARY\n")
            w("=" * 60 + "\n\n")
            w("File : %s\n" % os.path.abspath(target))
            w("Size : %s\n" % _human(size))
            if meta.get("packaging") == "onefile":
                w("Type : one-file (self-extracting). Payload was unpacked.\n")
            w("\n")
            w("WHAT IS IN THIS FOLDER\n")
            w("-" * 60 + "\n")
            w("START_HERE.txt   this file\n")
            w("report.txt       modules, function names, embedded paths\n")
            w("strings.txt      every text string in the program (%d)\n" % n_strings)
            w("evidence.txt     per-function clues for rebuilding code\n")
            w("prompt.txt       paste into an LLM to rebuild the bodies\n")
            w("skeleton/        exact module tree with true signatures\n")
            if pycs:
                w("bytecode/        %d recovered .pyc files (LOSSLESS)\n" % len(pycs))
                w("decompiled/      readable source for %d of them\n" % n_decomp)
            w("\n")
            w("HOW MUCH WAS RECOVERED\n")
            w("-" * 60 + "\n")
            w("Modules identified   : %d\n" % len(real))
            w("Functions recovered  : %d\n" % n_funcs)
            w("String literals      : %d\n" % n_strings)
            w("Lossless bytecode    : %d module(s)\n" % len(pycs))
            w("Decompiled to source : %d file(s)\n" % n_decomp)
            w("\n")
            w("WHAT WAS NOT RECOVERED\n")
            w("-" * 60 + "\n")
            if pycs:
                w("The %d modules in decompiled/ came back complete - check those\n"
                  % n_decomp)
                w("first, they are effectively the original code.\n\n")
            w("For every other module:\n")
            w("  - function bodies (compiled to machine code, not in the file)\n")
            w("  - comments and formatting (never survive any compiler)\n")
            w("  - builtin names such as len/sum/range (compiled to C calls)\n")
            w("\n")
            w("NEXT STEP\n")
            w("-" * 60 + "\n")
            w("1. Look in decompiled/ first. If it has files, that is your code back.\n")
            w("2. Otherwise open prompt.txt, paste the whole thing into an LLM,\n")
            w("   and add: 'Rebuild these modules from the evidence.'\n")
            w("3. TEST what comes back before trusting it. The names and literals\n")
            w("   are exact, but loops and operators were inferred, so it will pass\n")
            w("   the happy path and can fail on edge cases.\n")


def current_pyc_magic():
    """The running interpreter's .pyc magic, as an int."""
    try:
        import importlib.util
        return struct.unpack("<I", importlib.util.MAGIC_NUMBER)[0]
    except Exception:
        return PYC_MAGIC.get(sys.version_info[:2], 0x0A0D0DA7)


# ===========================================================================
# GUI
# ===========================================================================

LOG_COLORS = {
    "info": "#d4d4d4",
    "ok": "#6ac46a",
    "warn": "#e0b050",
    "err": "#e06c6c",
    "head": "#6cb6e0",
}


class App(object):
    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk

        self.tk = tk
        self.ttk = ttk
        self.root = root
        self.target = None
        self.worker = None
        self.queue = queue.Queue()
        self.running = False

        root.title("Nuitka Recovery Tool")
        root.geometry("880x620")
        root.minsize(720, 480)

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass

        # ---- top: file selection --------------------------------------
        top = ttk.Frame(root, padding=(12, 12, 12, 6))
        top.pack(fill="x")

        ttk.Label(top, text="1. Load your file", font=("", 10, "bold")).grid(
            row=0, column=0, columnspan=4, sticky="w", pady=(0, 6))

        self.btn_load = ttk.Button(top, text="Load EXE...", command=self.load_file)
        self.btn_load.grid(row=1, column=0, sticky="w")

        self.lbl_file = ttk.Label(top, text="No file loaded", foreground="#888")
        self.lbl_file.grid(row=1, column=1, columnspan=3, sticky="w", padx=(10, 0))

        ttk.Label(top, text="Output folder").grid(
            row=2, column=0, sticky="w", pady=(10, 0))
        self.var_out = tk.StringVar(value=os.path.join(HERE, "results"))
        self.ent_out = ttk.Entry(top, textvariable=self.var_out)
        self.ent_out.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(10, 6),
                          pady=(10, 0))
        self.btn_out = ttk.Button(top, text="Change...", command=self.choose_out)
        self.btn_out.grid(row=2, column=3, sticky="e", pady=(10, 0))

        top.columnconfigure(1, weight=1)

        # ---- middle: actions ------------------------------------------
        mid = ttk.Frame(root, padding=(12, 0, 12, 6))
        mid.pack(fill="x")

        ttk.Label(mid, text="2. Recover", font=("", 10, "bold")).pack(
            anchor="w", pady=(4, 6))

        row = ttk.Frame(mid)
        row.pack(fill="x")

        self.btn_start = ttk.Button(row, text="\u25b6  Start", command=self.start)
        self.btn_start.pack(side="left")

        self.btn_open = ttk.Button(row, text="Open Results Folder",
                                   command=self.open_results, state="disabled")
        self.btn_open.pack(side="left", padx=(8, 0))

        self.btn_clear = ttk.Button(row, text="Clear Log", command=self.clear_log)
        self.btn_clear.pack(side="left", padx=(8, 0))

        self.progress = ttk.Progressbar(row, mode="indeterminate", length=180)
        self.progress.pack(side="right")

        # ---- log -------------------------------------------------------
        body = ttk.Frame(root, padding=(12, 0, 12, 6))
        body.pack(fill="both", expand=True)

        ttk.Label(body, text="3. Live log", font=("", 10, "bold")).pack(
            anchor="w", pady=(4, 6))

        wrap = ttk.Frame(body)
        wrap.pack(fill="both", expand=True)

        self.log_widget = tk.Text(
            wrap, wrap="word", bg="#1e1e1e", fg="#d4d4d4",
            insertbackground="#d4d4d4", relief="flat", padx=10, pady=8,
            font=("Consolas" if os.name == "nt" else "Monospace", 9),
        )
        scroll = ttk.Scrollbar(wrap, command=self.log_widget.yview)
        self.log_widget.configure(yscrollcommand=scroll.set)
        self.log_widget.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.log_widget.configure(state="disabled")

        for name, colour in LOG_COLORS.items():
            self.log_widget.tag_configure(name, foreground=colour)

        # ---- status bar ------------------------------------------------
        self.var_status = tk.StringVar(value="Ready. Load a file to begin.")
        bar = ttk.Frame(root, padding=(12, 4, 12, 10))
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=self.var_status).pack(side="left")

        root.after(100, self._drain)

    # -- logging ---------------------------------------------------------

    def log(self, message, level="info"):
        self.queue.put((message, level))

    def _drain(self):
        try:
            while True:
                message, level = self.queue.get_nowait()
                self.log_widget.configure(state="normal")
                self.log_widget.insert("end", message + "\n", level)
                self.log_widget.see("end")
                self.log_widget.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self._drain)

    def clear_log(self):
        self.log_widget.configure(state="normal")
        self.log_widget.delete("1.0", "end")
        self.log_widget.configure(state="disabled")

    # -- actions ---------------------------------------------------------

    def load_file(self):
        from tkinter import filedialog, messagebox

        path = filedialog.askopenfilename(
            title="Choose a Nuitka-built executable",
            filetypes=[
                ("Executables", "*.exe *.bin *.elf"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        self.target = path
        name = os.path.basename(path)
        size = _human(os.path.getsize(path))
        self.lbl_file.configure(text="loaded  %s   (%s)" % (name, size),
                                foreground="#d4d4d4")
        self.log("Loaded %s" % name, "ok")
        self.log("   %s   %s" % (path, size))
        self.var_status.set("Loaded %s - press Start." % name)

        # Default the output next to the input file.
        base = os.path.splitext(name)[0]
        self.var_out.set(os.path.join(HERE, "results", base))

    def choose_out(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Choose output folder")
        if d:
            self.var_out.set(d)

    def start(self):
        from tkinter import messagebox

        if self.running:
            return
        if not self.target:
            messagebox.showinfo("No file", "Load a file first.")
            return

        outdir = self.var_out.get().strip()
        if not outdir:
            messagebox.showinfo("No output folder", "Choose an output folder.")
            return

        self.running = True
        self.btn_start.configure(state="disabled")
        self.btn_load.configure(state="disabled")
        self.btn_open.configure(state="disabled")
        self.progress.start(12)
        self.var_status.set("Working ...")

        self.log("")
        self.log("=" * 60, "head")
        self.log("Starting extraction: %s" % os.path.basename(self.target), "head")
        self.log("=" * 60, "head")

        def work():
            code = 1
            try:
                engine = Engine(log=self.log)
                code = engine.run(self.target, outdir)
                self.queue.put(("__DONE__", str(code)))
            except Exception as exc:
                import traceback
                self.log("Unexpected error: %s" % exc, "err")
                for line in traceback.format_exc().splitlines():
                    self.log("   " + line, "err")
                self.queue.put(("__DONE__", "1"))

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        self.root.after(200, self._check_done)
        self._outdir = outdir

    def _check_done(self):
        done = None
        try:
            while True:
                msg, level = self.queue.get_nowait()
                if msg == "__DONE__":
                    done = level
                    break
                self.log_widget.configure(state="normal")
                self.log_widget.insert("end", msg + "\n", level)
                self.log_widget.see("end")
                self.log_widget.configure(state="disabled")
        except queue.Empty:
            pass

        if done is None:
            self.root.after(200, self._check_done)
            return

        self.running = False
        self.progress.stop()
        self.btn_start.configure(state="normal")
        self.btn_load.configure(state="normal")

        if done == "0":
            self.btn_open.configure(state="normal")
            self.var_status.set("Finished. Results in %s" % self._outdir)
            self.log("")
            self.log("Finished successfully.", "ok")
        else:
            self.var_status.set("Finished with problems - see the log.")
            self.log("")
            self.log("Finished with problems. See the log above.", "err")

    def open_results(self):
        d = getattr(self, "_outdir", None) or self.var_out.get()
        if not d or not os.path.isdir(d):
            return
        try:
            if os.name == "nt":
                os.startfile(d)  # noqa: S606
            elif sys.platform == "darwin":
                subprocess.Popen(["open", d])
            else:
                subprocess.Popen(["xdg-open", d])
        except Exception as exc:
            from tkinter import messagebox
            messagebox.showinfo("Open folder", "Could not open automatically.\n"
                                              "It is here:\n%s" % d)


# ===========================================================================
# COMMAND LINE
# ===========================================================================


def run_cli(argv):
    ap = argparse.ArgumentParser(
        description="Recover information from a Nuitka-built executable.")
    ap.add_argument("target")
    ap.add_argument("-o", "--outdir", default=None,
                    help="output folder (default: results/<name>)")
    args = ap.parse_args(argv)

    if args.outdir is None:
        base = os.path.splitext(os.path.basename(args.target))[0]
        args.outdir = os.path.join(HERE, "results", base)

    def log(msg, level="info"):
        print(msg)
        sys.stdout.flush()

    return Engine(log=log).run(args.target, args.outdir)


def main():
    argv = sys.argv[1:]

    # Command-line mode when given a path, or when tkinter is unavailable.
    if argv and not argv[0].startswith("-"):
        return run_cli(argv)

    try:
        import tkinter as tk
    except ImportError:
        print("tkinter is not available, so the GUI cannot start.\n"
              "Run it from the command line instead:\n\n"
              "    python3 %s yourfile.exe\n" % os.path.basename(__file__))
        return 2

    try:
        root = tk.Tk()
    except Exception as exc:
        print("Could not open a window (%s).\n"
              "Run from the command line instead:\n\n"
              "    python3 %s yourfile.exe\n" % (exc, os.path.basename(__file__)))
        return 2

    App(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def build():
    nf = read(os.path.join(HERE, "nuitka_forensics.py"))
    rc = read(os.path.join(HERE, "reconstruct.py"))

    # nuitka_forensics: keep from TOOL_VERSION up to the CLI main()
    start = nf.index('TOOL_VERSION = "2.0"')
    end = nf.index("\ndef main(argv=None):")
    nf_body = nf[start:end]
    nf_body = nf_body.replace("TOOL_VERSION = ", "TOOL_VERSION = ", 1)

    # reconstruct: keep from the classifier section up to its CLI main()
    start = rc.index("# Heuristic classification of a bare string constant")
    end = rc.index("\ndef main(argv=None):")
    rc_body = rc[start:end]

    # Drop the cross-module import guard which no longer applies.
    rc_body = rc_body.replace("sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))\n", "")

    parts = [
        HEADER,
        "# =========================================================================\n"
        "# PART 1: the constants-blob decoder\n"
        "#   Format reconstructed from Nuitka's own sources:\n"
        "#     build/include/nuitka/constants_blob_spec.h   tag byte values\n"
        "#     build/static_src/HelpersConstantsBlob.c      runtime decoder\n"
        "#     tools/data_composer/DataComposer.py          build-time encoder\n"
        "# =========================================================================\n\n",
        nf_body.strip() + "\n",
        "\n\n" + "# =========================================================================\n"
        "# PART 2: per-function evidence extraction\n"
        "# =========================================================================\n\n",
        rc_body.strip() + "\n",
        GUI,
    ]

    text = "".join(parts)

    # The spliced bodies were written as separate modules; make sure nothing
    # still refers to them by name.
    for bad in ("nuitka_forensics.", "reconstruct.", "\nimport nuitka_forensics",
                "\nimport reconstruct"):
        if bad in text:
            raise SystemExit("merge error: leftover reference %r" % bad)

    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)

    print("wrote %s (%d lines, %d bytes)" % (OUT, text.count("\n") + 1, len(text)))


if __name__ == "__main__":
    build()
