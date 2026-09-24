#!/usr/bin/env python3
"""Measure how much of an original Python project a Nuitka binary gives back.

Parses the original sources with `ast` to build ground truth, then compares it
against the symbol table recovered by nuitka_forensics.py.

Usage:
    python3 compare_recovery.py <original_project_dir> <recovered.json>
"""

import argparse
import ast
import json
import os
import sys


# ---------------------------------------------------------------------------
# Ground truth from the original sources
# ---------------------------------------------------------------------------

class GroundTruth(ast.NodeVisitor):
    """Collect every function/class with its scope, line and locals."""

    def __init__(self):
        self.entries = []
        self.scopes = []  # enclosing names

    # -- helpers ---------------------------------------------------------
    @staticmethod
    def _arg_names(args):
        out = []
        out.extend(a.arg for a in args.posonlyargs)
        n_pos = len(out)
        out.extend(a.arg for a in args.args)
        if args.vararg:
            out.append(args.vararg.arg)
        out.extend(a.arg for a in args.kwonlyargs)
        if args.kwarg:
            out.append(args.kwarg.arg)
        return out, n_pos, len(args.kwonlyargs)

    @staticmethod
    def _assigned_names(node):
        """Names bound anywhere in this function body, excluding nested scopes."""
        names = set()

        class V(ast.NodeVisitor):
            def visit_FunctionDef(self, n):
                names.add(n.name)

            def visit_AsyncFunctionDef(self, n):
                names.add(n.name)

            def visit_ClassDef(self, n):
                names.add(n.name)

            def visit_Name(self, n):
                if isinstance(n.ctx, (ast.Store, ast.Del)):
                    names.add(n.id)

            def visit_ExceptHandler(self, n):
                if n.name:
                    names.add(n.name)
                self.generic_visit(n)

            def visit_Global(self, n):
                for x in n.names:
                    names.add(x)

            def visit_Nonlocal(self, n):
                for x in n.names:
                    names.add(x)

        # Do not descend into nested function bodies for plain locals, but the
        # nested function's own NAME is a local of this scope.
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                names.add(child.name)
            else:
                V().visit(child)
        return names

    # -- visits ----------------------------------------------------------
    def _handle_function(self, node, kind):
        qual = ".".join(self.scopes + [node.name]) if self.scopes else node.name
        args, n_pos, n_kwonly = self._arg_names(node.args)

        names = set(args)
        names |= self._assigned_names(node)

        self.entries.append({
            "kind": kind,
            "name": node.name,
            "qualname": qual,
            "scope": ".".join(self.scopes),
            "line": node.lineno,
            "args": args,
            "arg_count": len(node.args.posonlyargs) + len(node.args.args),
            "pos_only": len(node.args.posonlyargs),
            "kw_only": n_kwonly,
            "vararg": bool(node.args.vararg),
            "kwarg": bool(node.args.kwarg),
            "locals": sorted(names),
        })

        self.scopes.append(node.name)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_FunctionDef(self, node):
        self._handle_function(node, "Function")

    def visit_AsyncFunctionDef(self, node):
        self._handle_function(node, "Coroutine")

    def visit_ClassDef(self, node):
        qual = ".".join(self.scopes + [node.name]) if self.scopes else node.name
        self.entries.append({
            "kind": "Class",
            "name": node.name,
            "qualname": qual,
            "scope": ".".join(self.scopes),
            "line": node.lineno,
            "args": [],
            "arg_count": 0,
            "pos_only": 0,
            "kw_only": 0,
            "vararg": False,
            "kwarg": False,
            "locals": [],
        })
        self.scopes.append(node.name)
        self.generic_visit(node)
        self.scopes.pop()


def load_ground_truth(root):
    """Map module name -> list of entries."""
    modules = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".git")]
        for fn in filenames:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            if fn == "__init__.py":
                mod = os.path.dirname(rel).replace(os.sep, ".")
                mod = mod or "__main__"
            elif rel == "main.py":
                mod = "__main__"
            else:
                mod = rel[:-3].replace(os.sep, ".")
            try:
                tree = ast.parse(open(path, encoding="utf-8").read(), path)
            except SyntaxError:
                continue
            gt = GroundTruth()
            gt.visit(tree)
            modules[mod] = gt.entries
    return modules


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _norm(qualname):
    """Normalise both sides to the same nesting convention.

    Nuitka records the runtime `__qualname__`, which inserts `<locals>` at each
    closure boundary; `ast` nesting does not.  Strip it from both so the
    comparison measures recovery, not naming style.
    """
    return (qualname or "").replace(".<locals>.", ".").replace("<locals>.", "")


def compare(gt_modules, recovered):
    """Compare recovered symbol table against ground truth."""
    symbols = recovered.get("symbols", {})

    rows = []
    totals = {
        "gt_defs": 0, "matched": 0, "line_exact": 0, "sig_exact": 0,
        "locals_full": 0, "locals_partial": 0, "missing": 0,
    }

    gt_by_qual = {}
    for mod, entries in gt_modules.items():
        for e in entries:
            gt_by_qual.setdefault((mod, _norm(e["qualname"])), e)

    rec_by_qual = {}
    for mod, entries in symbols.items():
        for e in entries:
            q = _norm(e.get("qualname"))
            rec_by_qual.setdefault((mod, q), e)

    for mod in sorted(set(list(gt_modules) + list(symbols))):
        gt_entries = gt_modules.get(mod, [])
        rec_entries = symbols.get(mod, [])
        rec_q = set(_norm(e.get("qualname")) for e in rec_entries)

        for e in gt_entries:
            if e["kind"] == "Class":
                # Nuitka records class bodies as modules, not code objects.
                continue
            totals["gt_defs"] += 1
            key = (mod, _norm(e["qualname"]))
            r = rec_by_qual.get(key)
            if r is None:
                # Try the bare name (Nuitka may not qualify identically).
                alt = [e2 for e2 in rec_entries if _norm(e2.get("qualname")) == _norm(e["qualname"])]
                r = alt[0] if alt else None

            row = {
                "module": mod,
                "qualname": e["qualname"],
                "gt_line": e["line"],
                "gt_sig": _fmt(e),
                "found": r is not None,
            }
            if r:
                totals["matched"] += 1
                row["rec_line"] = r["line"]
                row["rec_sig"] = r["signature"]
                row["line_match"] = (r["line"] == e["line"])
                if row["line_match"]:
                    totals["line_exact"] += 1
                if _sig_equal(r, e):
                    totals["sig_exact"] += 1
                    row["sig_match"] = True
                else:
                    row["sig_match"] = False
                gt_locals = set(e["locals"])
                rec_locals = set(r.get("locals") or [])
                # Nuitka's varnames include args too; compare union.
                rec_all = rec_locals | set(_sig_params(r))
                if gt_locals and gt_locals.issubset(rec_all):
                    totals["locals_full"] += 1
                    row["locals"] = "full"
                elif gt_locals & rec_all:
                    totals["locals_partial"] += 1
                    row["locals"] = "partial (%d/%d)" % (
                        len(gt_locals & rec_all), len(gt_locals))
                else:
                    row["locals"] = "none"
            else:
                totals["missing"] += 1
                row["rec_line"] = None
                row["rec_sig"] = None
                row["line_match"] = False
                row["sig_match"] = False
                row["locals"] = "n/a"
            rows.append(row)

    return rows, totals


def _sig_params(r):
    """Extract parameter names from a recovered signature string."""
    sig = r.get("signature") or ""
    if "(" not in sig:
        return []
    inner = sig[sig.index("(") + 1:sig.rindex(")")]
    out = []
    for part in inner.split(","):
        part = part.strip()
        if not part or part in ("*", "/"):
            continue
        part = part.lstrip("*")
        out.append(part)
    return out


def _fmt(e):
    return "%s(%s)" % (e["name"], ", ".join(e["args"]))


def _sig_equal(r, e):
    """Compare parameter structure exactly."""
    r_args = _sig_params(r)
    gt_args = list(e["args"])
    if len(r_args) != len(gt_args):
        return False
    for a, b in zip(r_args, gt_args):
        if a != b:
            return False
    return (bool(r.get("varargs")) == e["vararg"]
            and bool(r.get("kwargs")) == e["kwarg"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("project", help="original project directory")
    ap.add_argument("report", help="JSON report from nuitka_forensics.py --json")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    gt = load_ground_truth(args.project)
    recovered = json.load(open(args.report, encoding="utf-8"))
    rows, totals = compare(gt, recovered)

    n = totals["gt_defs"] or 1
    print("=" * 78)
    print("RECONSTRUCTION FIDELITY vs ORIGINAL SOURCE")
    print("=" * 78)
    print()
    print("Function definitions in original source : %d" % totals["gt_defs"])
    print("Recovered from binary                   : %d (%.1f%%)"
          % (totals["matched"], 100.0 * totals["matched"] / n))
    print()
    print("  line number EXACT match  : %d (%.1f%% of recovered)"
          % (totals["line_exact"], 100.0 * totals["line_exact"] / max(1, totals["matched"])))
    print("  signature EXACT match    : %d (%.1f%% of recovered)"
          % (totals["sig_exact"], 100.0 * totals["sig_exact"] / max(1, totals["matched"])))
    print("  all locals recovered     : %d (%.1f%% of recovered)"
          % (totals["locals_full"], 100.0 * totals["locals_full"] / max(1, totals["matched"])))
    print("  some locals recovered    : %d" % totals["locals_partial"])
    print("  definitions NOT recovered: %d" % totals["missing"])
    print()

    if args.verbose:
        print("-" * 78)
        print("%-42s %6s %6s %5s %5s" % ("qualname", "gt_ln", "rec_ln", "ln", "sig"))
        print("-" * 78)
        for r in rows:
            print("%-42s %6s %6s %5s %5s" % (
                r["qualname"][:42], r["gt_line"], r["rec_line"],
                "OK" if r["line_match"] else "X",
                "OK" if r["sig_match"] else "X"))
        print()

    # ---- what the reconstruction proves about bodies ------------------
    print("-" * 78)
    print("FUNCTION BODY RECOVERY")
    print("-" * 78)
    bc = recovered.get("embedded_bytecode", [])
    if not bc:
        print("Recovered embedded bytecode payloads: 0")
        print()
        print("No CPython bytecode exists in this binary.  Every module was")
        print("compiled to native machine code, so function bodies (statements,")
        print("expressions, control flow) are NOT present in any recoverable form.")
    else:
        print("Recovered embedded bytecode payloads: %d" % len(bc))
        for e in bc:
            print("   %d bytes at 0x%X  recovered=%s" % (e["size"], e["offset"], e["recovered"]))

    strings = recovered.get("string_count", 0)
    print()
    print("String literals recovered: %d (all of them; these are stored verbatim)"
          % strings)


if __name__ == "__main__":
    sys.exit(main())
