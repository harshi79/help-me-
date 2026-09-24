# Nuitka Recovery Tool

A single-file GUI tool for inspecting Nuitka-built executables: load the file,
watch the log, get the results in a folder.

```
decompile.py      <- the whole tool, one file
```

## Using it

**Graphical:**

```bash
python3 decompile.py
```

A window opens. Click **Load EXE...**, pick your file, click **Start**. The log
streams live and the results land in a `results/<yourfile>/` folder. There's an
**Open Results Folder** button when it finishes.

**Command line** (same result, no window):

```bash
python3 decompile.py yourfile.exe
python3 decompile.py yourfile.exe -o my_results
```

Command-line mode is also used automatically if tkinter isn't installed.

## Requirements

* **Python 3.8+**
* **tkinter** for the GUI - already included with the standard Python installers
  on Windows and macOS. On minimal Linux installs you may need
  `apt install python3-tk`.
* **zstandard** - only needed for single-file (self-extracting) executables,
  which is most of them:

  ```bash
  pip install zstandard
  ```

* **pycdc** (optional) - only needed to turn recovered bytecode back into
  readable source. Without it you still get the `.pyc` files, which are valid
  and can be decompiled later.

## What it gets you

Nuitka compiles Python to C and then to machine code. It doesn't obfuscate
anything, and it leaves a *constants blob* in the binary that holds real
information. This tool decodes that.

| Recovered | Notes |
|---|---|
| Module list and package structure | including original source file paths |
| Every string literal | API keys, URLs, error messages, all of it |
| Function/method/lambda names | with full qualified nesting |
| Exact parameter signatures | arity, `/`, `*`, `*args`, `**kwargs` |
| Every local variable name | per function |
| Line number of every `def` | |
| Generator / coroutine / async flags | |
| Identifier and literal evidence per function | enough to rebuild bodies |
| **Real CPython bytecode** | for modules Nuitka left uncompiled - lossless |

## What it can't get you

* **Function bodies of compiled modules.** They're machine code. Not in the file
  in any recoverable form. This is a compilation boundary, not a tool
  limitation, and no tool currently reverses it.
* **Comments and formatting.** Never survive any compiler.
* **Builtin names** like `len`, `sum`, `range` - compiled to direct C calls, so
  they never exist as strings.

## Results folder

```
START_HERE.txt   summary for your specific file - read this first
report.txt       modules, function names, embedded paths
strings.txt      every text string in the program
evidence.txt     per-function clues for rebuilding code
prompt.txt       paste into an LLM to rebuild the bodies
skeleton/        your project tree with real signatures
bytecode/        recovered .pyc files (only if any module was uncompiled)
decompiled/      readable source for those modules - check this first
```

### Getting the code back

If `decompiled/` has files in it, those are effectively your original modules.
Look there first.

Otherwise, paste `prompt.txt` into an LLM and ask it to rebuild the modules. The
names, signatures and literals it works from are exact, but the loop and
expression structure is inferred - so treat the output as a close
approximation and **test it before trusting it**.

## Verified against ground truth

Validated on test binaries built with Nuitka 4.2.2 / CPython 3.11.2, checked
against the compiler's own build directory:

* Constants decoded match the compiler's manifest exactly (251/251)
* 13/13 function definitions recovered with **100% exact line numbers and 100%
  exact signatures**
* 4/4 demoted modules recovered with **byte-identical bytecode**, then
  decompiled back to readable source
* One-file builds: payload unpacked, **284 modules recovered losslessly**, 279
  decompiled to source, in 2.4 seconds

## Repository layout

```
decompile.py                     the tool - one self-contained file
nuitka-forensics/
    QUICKSTART.md                plain-English usage guide
    FINDINGS.md                  full technical report + binary format spec
    nuitka_forensics.py          stage 1: the analyser
    reconstruct.py               stage 2: per-function evidence
    run.py                       pipeline driver (predecessor of decompile.py)
    compare_recovery.py          measures reconstruction accuracy
    build_single_file.py         regenerates decompile.py from the modules
    test_gui_smoke.py            exercises the GUI headlessly
    testdata/                    a sample project to try it on
```

`decompile.py` is generated from the modules in `nuitka-forensics/` so the tested
decoder isn't duplicated by hand. To rebuild it after changing a module:

```bash
python3 nuitka-forensics/build_single_file.py
```

## Testing it yourself

There's a small sample project in `nuitka-forensics/testdata/specimen/`. Build
it with Nuitka, run `decompile.py` on the result, and compare what comes back
against the original source.

## Author's notes on honesty

Everything above was measured, not assumed. Where something didn't work, or
couldn't be tested, it says so in `FINDINGS.md` - including that the Windows PE
path is implemented but was not exercised on a real Windows binary, because this
work was done in a Linux environment.

If someone claims to have recovered your *exact* original source from a Nuitka
binary: if the code they produced contains your comments, they had your actual
files. If it has no comments, it was reconstructed - and it will look right
while breaking on edge cases.
