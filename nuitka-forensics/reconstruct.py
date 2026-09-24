#!/usr/bin/env python3
#     Reconstruction stage for Nuitka binaries.
#
#     nuitka_forensics.py answers "what is in the file".
#     This answers "given that, what did the source probably look like".
#
#     It works from a property of Nuitka's constants blob that is easy to miss:
#     constants are emitted roughly in source order, and each function's
#     code-object record is emitted at the point that function is compiled.  So
#     the constants sitting next to a code-object record are that function's
#     own identifiers, literals, attributes and slice objects.
#
#     Concretely, for a function the binary yields:
#
#       exact  : name, parameter list, arity, *args/**kwargs, local variable
#                names, def line number, generator/coroutine kind
#       exact  : every global/import name it references
#       exact  : every attribute it accesses, in order          (obj.NAME)
#       exact  : every string/bytes/number literal in its body
#       exact  : every slice expression, e.g. [:32]
#       likely : its default argument values
#
#     What it does NOT yield: statement structure, operators, control flow,
#     call nesting, comments.  Those must be inferred.
#
#     So the output of this tool is EVIDENCE, not source.  It is exactly the
#     input an LLM needs, and exactly the reason a good reconstruction can be
#     "very close" while still not being the original.

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nuitka_forensics import (  # noqa: E402
    BlobDataValue,
    CodeObjectRecord,
    F_KW_ONLY,
    F_OPTIMIZED,
    F_POS_ONLY,
    F_VARARGS,
    F_VARKEYWORDS,
    analyse,
    find_blobs,
    load_blobs,
)


# ---------------------------------------------------------------------------
# Heuristic classification of a bare string constant
# ---------------------------------------------------------------------------
#
# Inside a function's constant window, a string is one of:
#   - an attribute name        (obj.NAME)      - no spaces, valid identifier
#   - a global/import name     (NAME)          - valid identifier, referenced
#   - a format string          ("%s:%s")
#   - a user-visible literal   ("invoice settlement")
#
# We cannot always tell an attribute from a global, but both are useful: the
# pair (GLOBAL then ATTRIBUTE) is almost always `global.attribute(...)`.

_IDENT_RE = __import__("re").compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_DUNDER_RE = __import__("re").compile(r"^__[A-Za-z_]+__$")
_FORMAT_HINT = __import__("re").compile(r"%[sdrf%]")


def classify_string(s, func):
    """Best-effort role of a string constant within a function."""
    if _DUNDER_RE.match(s):
        return "dunder"
    if s == func.name:
        return "self-name"
    if s in func.locals:
        return "local-name"
    if _IDENT_RE.match(s):
        if s in func.locals:
            return "local-name"
        if s[0].isupper():
            return "class-or-constant"
        return "attribute-or-global"
    if _FORMAT_HINT.search(s):
        return "format-string"
    return "literal"


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------

class FuncEvidence(object):
    __slots__ = (
        "name", "qualname", "kind", "line", "signature", "params",
        "locals", "freevars", "flags", "constants", "blobs", "defaults",
        "module", "module_path",
    )

    def __init__(self):
        self.name = "?"
        self.qualname = "?"
        self.kind = "?"
        self.line = 0
        self.signature = "?"
        self.params = []
        self.locals = []
        self.freevars = []
        self.flags = 0
        self.constants = []      # (value, role)
        self.blobs = []
        self.defaults = None
        self.module = "?"
        self.module_path = "?"

    @property
    def is_function(self):
        return bool(self.flags & F_OPTIMIZED)

    def attributes(self):
        """Identifier constants that look like attribute accesses."""
        return [v for v, r in self.constants
                if r == "attribute-or-global" and _IDENT_RE.match(v)]

    def globals_(self):
        return [v for v, r in self.constants
                if r in ("attribute-or-global", "class-or-constant")]

    def literals(self):
        return [v for v, r in self.constants if r in ("literal", "format-string")]

    def slices(self):
        return [v for v, _ in self.constants if isinstance(v, slice)]

    def numbers(self):
        return [v for v, _ in self.constants
                if isinstance(v, (int, float)) and not isinstance(v, bool)]


def extract_evidence(path, blob_name=None):
    """Return {module: [FuncEvidence, ...]} plus module metadata."""
    report, detail = analyse(path)
    if not report["blob"].get("found"):
        return None, report

    blobs, meta = load_blobs(path)
    if blobs is None:
        return None, report

    modules = OrderedDict()

    for blob in blobs:
        mod = blob.name or "<global pool>"
        if blob_name and mod != blob_name:
            continue

        values = blob.values
        ev = []
        current = None
        trailing = []          # constants after the last code object
        pool = []              # argument/import tuples

        for i, v in enumerate(values):
            if isinstance(v, CodeObjectRecord):
                if current is not None:
                    ev.append(current)
                current = FuncEvidence()
                current.name = v.name
                current.qualname = v.qualname
                current.kind = v.kind
                current.line = v.line_number
                current.flags = v.flags
                current.locals = list(v.var_names)
                current.freevars = list(v.free_vars)
                sig, _ = v.signature()
                current.signature = sig
                current.params = _params(v)
                current.module = mod
                continue

            if isinstance(v, BlobDataValue):
                if current is not None:
                    current.blobs.append((len(v.data), v.offset))
                continue

            if isinstance(v, tuple) and all(
                isinstance(x, (str, int, float, bool, type(None))) for x in v
            ):
                # Scalars-only tuples are default-argument or import-from lists.
                pool.append(v)
                continue

            if current is not None:
                role = classify_string(v, current) if isinstance(v, str) else type(v).__name__
                current.constants.append((v, role))
            else:
                trailing.append(v)

        if current is not None:
            ev.append(current)

        # Attach module path (last absolute path constant seen).
        mod_path = None
        for v in values:
            if isinstance(v, str) and (v.endswith(".py") and ("/" in v or "\\" in v)):
                mod_path = v
        for e in ev:
            e.module_path = mod_path or "?"

        leftovers = _pair_defaults(ev, pool)

        # The full ordered constant stream, with code-object markers inline.
        # Attribution by adjacency is high-confidence but not perfect, so the
        # complete stream is kept: a constant that appears before its own code
        # object would otherwise be lost.
        stream = []
        for v in values:
            if isinstance(v, CodeObjectRecord):
                stream.append(("MARK", "%s @%d [%s]" % (v.qualname, v.line_number, v.kind)))
            elif isinstance(v, BlobDataValue):
                stream.append(("BLOB", "%d bytes" % len(v.data)))
            else:
                stream.append((type(v).__name__, v))

        modules[mod] = {
            "functions": ev,
            "pool": pool,
            "leftover_tuples": leftovers or [],
            "stream": stream,
            "path": mod_path,
        }

    return modules, report


def _params(rec):
    sig = rec.signature()[0]
    inner = sig[sig.index("(") + 1:sig.rindex(")")]
    out = []
    for part in inner.split(","):
        part = part.strip()
        if not part or part in ("*", "/"):
            continue
        out.append(part.lstrip("*"))
    return out


_ALLCAPS_RE = __import__("re").compile(r"^[A-Z][A-Z0-9_]*$")


def _pair_defaults(ev_list, pool):
    """Pair scalar tuples to functions as default arguments.

    Heuristic.  Distinguishes `from mod import NAME` lists (all items are
    ALL_CAPS/identifier names) from real default values, then matches the rest
    to functions in source-line order subject to the arity bound.

    Labelled heuristic in all output - default attributes are usually reliable,
    the assignment of a tuple to a specific function less so.
    """
    value_tuples = []
    for t in pool:
        if not t:
            continue
        if all(isinstance(x, str) and _ALLCAPS_RE.match(x) for x in t):
            continue  # import-from list
        value_tuples.append(t)

    if not value_tuples:
        return

    used = set()
    # Functions in source order, skipping nested ones (they rarely have defaults
    # and would steal tuples from their parents).
    for e in sorted([x for x in ev_list if x.is_function], key=lambda x: x.line):
        if any(e.name in other.locals for other in ev_list if other is not e):
            continue
        if e.defaults is not None or not e.params:
            continue
        for idx, t in enumerate(value_tuples):
            if idx in used:
                continue
            if 1 <= len(t) <= max(1, len(e.params)):
                e.defaults = t
                used.add(idx)
                break

    # Whatever is left is still worth reporting.
    leftovers = [t for i, t in enumerate(value_tuples) if i not in used]
    return leftovers


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def render_module_card(mod, blob_info, show_pool=True):
    o = []
    p = o.append
    p("=" * 78)
    p("MODULE: %s" % mod)
    p("=" * 78)
    path = blob_info.get("path")
    if path:
        p("original source path : %s" % path)
    p("functions recovered  : %d" % len(blob_info["functions"]))
    p("")

    for e in blob_info["functions"]:
        p("-" * 78)
        p("  def %s        # line %d" % (e.signature, e.line))
        p("-" * 78)
        p("  kind        : %s" % e.kind)
        p("  qualname    : %s" % e.qualname)
        if e.locals:
            p("  locals      : %s" % ", ".join(e.locals))
        if e.freevars:
            p("  closure     : %s" % ", ".join(e.freevars))
        if e.defaults:
            p("  defaults    : %r" % (e.defaults,))

        if e.constants:
            p("  --- constants in source order (this is the body evidence) ---")
            for v, role in e.constants:
                p("      %-22s %r" % (role, v))
        else:
            p("  (no body constants captured)")

        if e.blobs:
            p("  embedded bytecode: %s" % ", ".join("%d bytes" % n for n, _ in e.blobs))
        p("")

    if show_pool and blob_info.get("pool"):
        p("  module-level scalar tuples (default args / import-from lists):")
        for t in blob_info["pool"]:
            p("      %r" % (t,))
        p("")

    if show_pool and blob_info.get("leftover_tuples"):
        p("  unassigned tuples (could not be matched to a function):")
        for t in blob_info["leftover_tuples"]:
            p("      %r" % (t,))
        p("")

    if show_pool and blob_info.get("stream"):
        p("-" * 78)
        p("  FULL ORDERED CONSTANT STREAM (nothing omitted)")
        p("-" * 78)
        p("  Order approximates source order. MARK rows are function boundaries.")
        p("  Constants between two MARKs usually belong to the first function,")
        p("  but a constant declared early in a function can be emitted before")
        p("  its own MARK. Cross-check with line numbers.")
        p("")
        for kind, v in blob_info["stream"]:
            if kind == "MARK":
                p("   >>> %s" % v)
            elif kind == "BLOB":
                p("       <blob %s>" % v)
            else:
                p("       %-10s %r" % (kind, v))
        p("")

    return "\n".join(o)


def render_prompt(modules, binary_name="the supplied program"):
    """Produce an LLM prompt that encodes every recovered constraint."""
    o = []
    p = o.append

    p("You are reconstructing Python source from metadata recovered from a")
    p("Nuitka-compiled binary. Recovered facts are EXACT; everything else must")
    p("be inferred and must be marked as inferred.")
    p("")
    p("RULES")
    p("1. Function names, parameter lists, local variable names, line numbers")
    p("   and generator/coroutine kinds are EXACT. Do not change them.")
    p("2. The constants listed for each function are EXACT and are in roughly")
    p("   source order. Attribute-or-global identifiers are names actually")
    p("   referenced by that function. Never invent identifiers.")
    p("3. Line numbers constrain body length: a function starting at line X")
    p("   followed by one starting at line Y has roughly Y-X lines of body.")
    p("4. Default argument tuples are EXACT when present.")
    p("5. Statement structure, operators, control flow and call nesting are NOT")
    p("   recoverable. Where you infer them, emit a comment:")
    p("       # INFERRED: <what you assumed>")
    p("6. Comments and formatting from the original are LOST. Do not pretend")
    p("   to reproduce them.")
    p("7. If the evidence does not determine a body, emit:")
    p("       raise NotImplementedError('body not recoverable')")
    p("   Do not fabricate plausible logic silently.")
    p("")
    p("Reconstruct the following modules, one file per module, preserving the")
    p("dotted package structure.")
    p("")

    for mod, info in modules.items():
        if mod.startswith("<") or mod.startswith(".") or not mod:
            continue
        p("=" * 70)
        p("MODULE %s" % mod)
        if info.get("path"):
            p("source path: %s" % info["path"])
        p("=" * 70)
        for e in info["functions"]:
            p("")
            p("def %s:  # line %d  [%s]" % (e.signature, e.line, e.kind))
            p("    locals: %s" % (", ".join(e.locals) or "-"))
            if e.defaults:
                p("    defaults: %r" % (e.defaults,))
            for v, role in e.constants:
                p("    %-22s %r" % (role, v))
        p("")

    return "\n".join(o)


def write_skeleton(modules, outdir):
    """Write a compileable skeleton: exact signatures, bodies marked."""
    written = []
    for mod, info in modules.items():
        # Skip the global pool and the ".bytecode" pseudo-blob; neither is a
        # Python module.
        if mod.startswith("<") or mod.startswith(".") or not mod:
            continue
        rel = mod.replace(".", os.sep)
        target = os.path.join(outdir, rel + ".py")
        os.makedirs(os.path.dirname(target), exist_ok=True)

        lines = [
            "# Reconstructed from a Nuitka binary - SKELETON, NOT RUNNABLE SOURCE.",
            "#",
            "# Everything below is EXACT: names, signatures, local variables,",
            "# line numbers, kind. Bodies were compiled to native code and are",
            "# NOT present in the binary.",
            "#",
            "# See evidence.txt for the per-function constant evidence, and",
            "# prompt.txt to drive an LLM reconstruction of the bodies.",
            "",
        ]
        for e in info["functions"]:
            lines.append("")
            lines.append("# line %d  kind=%s" % (e.line, e.kind))
            if e.defaults:
                lines.append("# default args: %r" % (e.defaults,))
            for v, role in e.constants:
                lines.append("#   %-20s %r" % (role, v))
            lines.append("def %s:" % e.signature)
            lines.append("    raise NotImplementedError('body not recoverable from binary')")

        with open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        written.append(target)
    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Extract per-function reconstruction evidence from a Nuitka binary.")
    ap.add_argument("target")
    ap.add_argument("-o", "--outdir", required=True,
                    help="directory for evidence.txt / prompt.txt / skeleton/")
    ap.add_argument("--module", help="only this module name")
    ap.add_argument("--json", metavar="FILE", help="structured evidence dump")
    args = ap.parse_args(argv)

    modules, report = extract_evidence(args.target, blob_name=args.module)
    if modules is None:
        print("No constants blob found - cannot reconstruct.")
        return 2

    os.makedirs(args.outdir, exist_ok=True)

    cards = [render_module_card(m, i) for m, i in modules.items()]
    evidence = "\n".join(cards)
    with open(os.path.join(args.outdir, "evidence.txt"), "w", encoding="utf-8") as f:
        f.write(evidence)

    prompt = render_prompt(modules, os.path.basename(args.target))
    with open(os.path.join(args.outdir, "prompt.txt"), "w", encoding="utf-8") as f:
        f.write(prompt)

    skel = write_skeleton(modules, os.path.join(args.outdir, "skeleton"))

    if args.json:
        dump = {}
        for m, i in modules.items():
            dump[m] = {
                "path": i.get("path"),
                "functions": [
                    {
                        "signature": e.signature,
                        "qualname": e.qualname,
                        "kind": e.kind,
                        "line": e.line,
                        "locals": e.locals,
                        "freevars": e.freevars,
                        "defaults": list(e.defaults) if e.defaults else None,
                        "constants": [[repr(v), r] for v, r in e.constants],
                    }
                    for e in i["functions"]
                ],
            }
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(dump, f, indent=2)

    print(evidence)
    print()
    print("=" * 78)
    print("WROTE")
    print("=" * 78)
    print("  %s/evidence.txt   per-function evidence (read this)" % args.outdir)
    print("  %s/prompt.txt     LLM prompt encoding every constraint" % args.outdir)
    print("  %s/skeleton/      exact signatures, bodies marked" % args.outdir)
    for w in skel:
        print("      %s" % w)
    return 0


if __name__ == "__main__":
    sys.exit(main())
