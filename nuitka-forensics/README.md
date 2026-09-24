# nuitka-forensics

Static-analysis toolkit for Nuitka-compiled executables (Windows PE, Linux ELF,
macOS Mach-O).

It recovers what Nuitka actually embeds at build time — which is substantially
more than most people assume — and it reports honestly on what is genuinely
gone.

## Quick start

```bash
python3 nuitka_forensics.py target.exe
```

For a `--onefile` build, compressed payloads need `zstandard`:

```bash
pip install zstandard
python3 nuitka_forensics.py target.exe
```

Other options:

```bash
python3 nuitka_forensics.py target.exe --json report.json      # machine-readable
python3 nuitka_forensics.py target.exe --strings               # every string literal
python3 nuitka_forensics.py target.exe --skeleton out/         # per-module symbol skeleton
```

To measure fidelity against a known original:

```bash
python3 compare_recovery.py /path/to/original_project report.json --verbose
```

## What it recovers

| Artefact | Recovered |
|---|---|
| Exact module list and package hierarchy | yes |
| Original source file paths of every module | yes |
| Every string / bytes / numeric literal | yes, verbatim |
| Every function, method, lambda, comprehension name | yes |
| Full qualified names including `<locals>` nesting | yes |
| Exact parameter signatures (arity, `/`, `*`, `*args`, `**kwargs`) | yes |
| Every local variable name in every function | yes |
| Source line number of every `def` | yes |
| Generator / coroutine / async-generator distinction | yes |
| Raw CPython bytecode for "demoted" modules | yes, byte-identical |
| Function bodies of normally compiled modules | **no — only native code** |
| Comments and formatting | **no — never in bytecode** |

## How it works

Nuitka's constants blob is a plain tagged binary stream. It is not encrypted,
not compressed and not obfuscated. This tool decodes it directly, using the
format reconstructed from:

* `nuitka/build/include/nuitka/constants_blob_spec.h` — tag byte values
* `nuitka/build/static_src/HelpersConstantsBlob.c` — the runtime decoder
* `nuitka/tools/data_composer/DataComposer.py` — the encoder

See `FINDINGS.md` for the full format specification and the validation results.

## Layout

```
nuitka_forensics.py    the analyser
compare_recovery.py    fidelity measurement against original source
FINDINGS.md            full technical report and format specification
```

## Safety

`nuitka_forensics.py` never executes the target and never imports code from it.
It reads the file as bytes and decodes data structures. It contains no
unpickling of attacker-controlled data and no dynamic import of target-derived
names.
