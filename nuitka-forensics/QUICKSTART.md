# How to use this — plain English

You have an `.exe` built with Nuitka and you want to know what is inside it.
This page is the short version. No theory.

---

## The whole thing is one command

```bash
python3 run.py yourfile.exe
```

That's it. It creates a folder called `recovered/` next to wherever you ran it,
and fills it with everything the binary gives up.

If you want the output somewhere else:

```bash
python3 run.py myapp.exe -o my_results
```

---

## Before you start

You need **Python 3.8 or newer**. Check with:

```bash
python3 --version
```

Then install one dependency, only needed if the file is a single self-extracting
EXE (most are):

```bash
pip install zstandard
```

That's everything. No compilers, no Ghidra, no setup.

---

## What you get

After running, open **`recovered/START_HERE.txt`** first. It tells you what was
found in your specific file.

| File | What it is |
|---|---|
| `START_HERE.txt` | Summary. **Read this first.** |
| `report.txt` | Technical report: module list, function names, embedded file paths |
| `strings.txt` | Every text string in the program, one per line |
| `evidence.txt` | Per-function clues for rebuilding the code |
| `prompt.txt` | Paste this into an LLM to rebuild the bodies |
| `skeleton/` | Your project's folder structure, with real function signatures |
| `bytecode/` | Recovered `.pyc` files — **only if** any module was left uncompiled |
| `decompiled/` | Readable source for those modules |

---

## Reading the result, honestly

**Open `decompiled/` first.** If there are files in it, those are essentially
your original modules back — real source, readable, complete. That's the jackpot.
Not every program has them; it depends on how it was built.

**Then look at `skeleton/`.** This is your project tree with every function name,
parameter list, variable name and line number intact. The bodies say
`raise NotImplementedError('body not recoverable from binary')` because the
bodies genuinely are not in the file. That is not a limitation of this tool —
it is what compilation does.

**`strings.txt` is worth a look even if nothing else works.** Every API key, URL,
error message and file path in the program is in there.

---

## If you want the actual code back, not just the bones

Differences between programming languages don't matter here — use whichever LLM
you have.

1. Open `prompt.txt`
2. Copy the **entire** contents
3. Paste it into ChatGPT / Claude / whatever you use
4. Add: *"Rebuild these modules from the evidence. Follow the rules exactly."*
5. **Save what it gives you, then test it**

That last step is not optional. Here is why.

### What the LLM output actually is

It is a **close approximation**, not your original file. The evidence it works
from is real — every function name, signature, variable name and string literal
is exact. But statement structure is not recoverable, so the model is *inferring*
the operators, loops and call order.

Practical result:

- Happy path: almost always works
- Edge cases, error handling, boundary conditions: **this is where it breaks**

So: **run your tests against it.** If you don't have tests, use it for reference
and rewrite the tricky parts yourself. Do not ship it blind.

This also means: if someone hands you code and claims it is your exact original
source, and it has no comments in it, it was reconstructed. If it *does* have
comments, they had your actual file.

---

## Common problems

**"No Nuitka constants blob found"**
Either it isn't a Nuitka build, or it's wrapped in a third-party protector (Themida,
VMProtect, Enigma). Tell me and I'll look at it.

**"zstandard module required"**
Run `pip install zstandard` and try again.

**"0 modules had bytecode embedded"**
Normal. It means every module was compiled to native code, so you get the
skeleton and evidence rather than full source.

**It's slow**
It shouldn't be. A 10 MB file takes under 2 seconds. A 50 MB file takes a few
seconds. If it hangs, something is wrong — tell me.

---

## Using it on my side instead

You don't have to run any of this. Upload the EXE and I'll run the whole pipeline
and hand you the results, plus a read on what the file actually is.

---

## The other two scripts

You do not need these to get results — `run.py` calls them for you.

- `nuitka_forensics.py` — the low-level analyser. Use it directly if you want the
  technical report on its own: `python3 nuitka_forensics.py target.exe`
- `compare_recovery.py` — measures how accurate a reconstruction is, when you have
  the original to compare against:
  `python3 compare_recovery.py original_project/ recovered/report.json`

---

## One last thing

If this is your own project, binary recovery is the *worst* option available.
Check for these first, in order:

1. Your Git repo / GitHub
2. A backup, cloud drive, or old laptop
3. `__pycache__` folders next to where it used to run
4. Your build machine or CI logs

Any of those gets you the real files in seconds. This tool is for when those are
genuinely gone.
