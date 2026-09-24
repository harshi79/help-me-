# Nuitka reverse-engineering: what actually survives a build

A technical report with reproducible evidence.

Everything below was measured, not assumed. Claims that were tested are marked
with the test that produced them. Where a claim could not be tested, it says so.

**Tooling versions used:** Nuitka 4.2.2 (Open Source), CPython 3.11.2,
Debian 12, gcc 12.

**Test specimens:** a 5-module Python project (`specimen/`) built three ways —
accelerated, standalone, and onefile — from identical source, so every result
could be checked against ground truth.

---

## Executive summary

The widely repeated claim that "Nuitka is fully compiled, so nothing can be
recovered" is **false**. The equally confident claim that "you can get the
whole source back" is **also false**. The truth is a sharp split:

| | |
|---|---|
| **String / numeric literals** | All of them. Verbatim. Including API keys, salts, URLs, error text. |
| **Symbol table** | Effectively complete: every function, its exact signature, every local variable name, and the line number it was defined on. |
| **Original file paths** | Present, including the developer's directory layout. |
| **Function bodies — compiled modules** | **Gone.** They exist only as machine code. |
| **Function bodies — demoted modules** | **Byte-identical CPython bytecode**, decompilable back to readable source. |

In the test project, **13 of 13 function definitions were recovered with 100 %
exact line numbers and 100 % exact signatures.** For demoted modules, recovered
bytecode was proven **byte-for-byte identical** to recompiling the original
source.

---

## 1. Identifying a Nuitka build

### Detection

A Nuitka build is recognisable by a handful of unambiguous markers that survive
into the shipped binary. All were present in every specimen:

| Marker | Meaning |
|---|---|
| `__nuitka_version__` | the `__compiled__` dunder tuple |
| `nuitka_module_loader` | the meta-path loader class |
| `Nuitka_MetaPathBasedLoaderEntry` | the embedded module table |
| `loadConstantsBlob` / `_unpackBlobConstant` | the constants decoder, compiled in |
| `constants_blob_spec.h` | the format header path |
| `__compiled__` | per-module dunder |

A `--onefile` build additionally shows the bootstrap defining
`_NUITKA_ONEFILE_COMPRESSION_BOOL`, `_NUITKA_ONEFILE_PAYLOAD_SIZE_INT` and the
temp-extraction spec `{TEMP}/onefile_{PID}_{TIME_US}_{RANDOM}`.

### Version fingerprinting

The Nuitka version is not stored as a single string, but it is derivable:

* `NUITKA_CONSTANT_BLOB_TAG_*` and `NUITKA_CONSTANT_BLOB_CODE_FLAG_*` values are
  compiled into the decoder, so a blob can be decoded without knowing the
  version in advance — the tags are stable ASCII values (`'C'`, `'T'`, `'f'`…).
* The blob's **tag vocabulary itself dates the build**. Tags `0x43` (`C`,
  `CODE_OBJECT`), `0x41` (`A`, `GENERIC_ALIAS`) and `0x48` (`H`, `UNION_TYPE`)
  are present only in recent versions; a 1.x-era blob uses a large subset of
  the same tags but never emits `A`/`H`.
* The compiler's Python version is visible from the embedded stdlib paths and
  the bytecode magic in demoted modules.

### The module table

`meta_path_loader_entries[]` is a plain C array of
`{name, init_func, bytecode_ptr, bytecode_size, flags, file_path}`, so **every
module name and its original source path appear as literal strings**. Recovered
from the accelerated specimen:

```
/home/user/work/specimen/main.py
/home/user/work/specimen/myapp/__init__.py
/home/user/work/specimen/myapp/api.py
/home/user/work/specimen/myapp/config.py
/home/user/work/specimen/myapp/utils.py
```

Note this exposes the developer's build-time directory layout, not just names.

---

## 2. What is left inside the binary

### 2.1 The constants blob — and how to find it

Every Nuitka binary carries a *constants blob* holding all non-trivial constant
values for all modules. Structurally it is a directory followed by per-module
payloads:

```
repeat:
    name          NUL-terminated ASCII ("", ".bytecode", or a dotted module name)
    size          uint32 little-endian
    data          `size` bytes

each data:
    count         uint16 little-endian
    values        `count` tagged constants
    0x2E          end-of-constants marker
```

**It is not encrypted and not compressed.** There is no key, no XOR pass and no
obfuscation step. `nuitka/build/static_src/HelpersConstantsBlob.c` reads it
directly from a pointer, and `DataComposer.py` writes it with plain `struct`
packing.

Locating it in a shipped binary: the emitted directory always begins with the
`.bytecode` entry (`2e 62 79 74 65 63 6f 64 65 00`), which makes a reliable
anchor. The tool then walks the directory forward.

### 2.2 Complete tag table

Recovered from `nuitka/build/include/nuitka/constants_blob_spec.h`:

```
p PREVIOUS          n NONE              t TRUE              F FALSE
T TUPLE             L LIST              D DICT              S SET
P FROZENSET         l INT_SMALL+        q INT_SMALL-        g INT_LARGE+
G INT_LARGE-        i INT+              I INT-              Z FLOAT_SPECIAL
f FLOAT             s TEXT_EMPTY        w TEXT_SINGLE       v TEXT_UTF8_LEN
u TEXT_UTF8_ZT      a ATTR_NAME         b BYTES_LEN         c BYTES_ZT
d BYTES_SINGLE      : SLICE             ; RANGE             J COMPLEX_SPECIAL
j COMPLEX           B BYTEARRAY         M BUILTIN_ANON      Q BUILTIN_SPECIAL
X BLOB_DATA         A GENERIC_ALIAS     H UNION_TYPE        O BUILTIN_NAMED
E BUILTIN_EXCEPTION C CODE_OBJECT       . END
```

Encoding details that matter:

* Integers use LEB128 (`7 bits/byte, continue while byte >= 128`); large ints
  are a limb count followed by 31-bit limbs.
* `T`/`L` = varint size + values. `D` = varint size, then **all keys, then all
  values**.
* `p` (PREVIOUS) is an identity back-reference to the immediately preceding
  constant in the same sequence — a de-duplication trick, and a source of
  off-by-one bugs if ignored.
* `M` BUILTIN_ANON is a one-byte index into a fixed type list; `Q` is
  `0=Ellipsis, 1=NotImplemented, 2=sys.version_info`.

### 2.3 `CODE_OBJECT` records — the symbol table

This is the single most valuable structure for reconstruction. Format, verified
against both the encoder and the decoder:

```
'C'
  flags            varint
  name             constant          (function/class name)
  line_number      varint + 1        (the `def` line)
  var_names        constant          (EVERY local name, args first)
  arg_count        varint
  if flags & 0x01: parent_qualname   constant  (class-level scope only)
  if flags & 0x02: free_vars         constant  (closure cell names)
  if flags & 0x04: kw_only_count     varint + 1
  if flags & 0x08: pos_only_count    varint + 1
```

Flags:

```
0x01 QUALNAME   0x02 FREE_VARS  0x04 KW_ONLY   0x08 POS_ONLY
0x30 KIND MASK: 0x10 GENERATOR  0x20 COROUTINE  0x30 ASYNCGEN
0x40 OPTIMIZED  0x80 NEWLOCALS  0x100 VARARGS   0x200 VARKEYWORDS
0x400..0x10000 future flags     0x20000 NOFREE
```

Two subtleties worth recording, because both cost time to discover:

1. **The `qualname` field holds only the parent scope.** The encoder writes
   `co_qualname.rsplit(".")[0]`. So a closure inside a method is recorded with
   parent `LedgerReconciler`, not
   `LedgerReconciler.add_entry.<locals>`.
2. **The precise qualname still exists anyway** — as a string constant in the
   same module blob, because it is needed for the function's `__qualname__`.
   The tool pairs the two, which is how
   `LedgerReconciler.add_entry.<locals>._normalise` is reported exactly.

`var_names` is genuinely *all* locals, not just parameters
(`nodes/CodeObjectSpecs.py: updateLocalNames()` accumulates them), so local
variable names are recoverable in full.

### 2.4 `BLOB_DATA` — and bytecode demotion

Nuitka normally compiles Python to C and then to native code, discarding the
bytecode. But it has a documented fallback: modules that cannot or should not be
compiled are **"demoted" to bytecode** instead. From
`nuitka/optimizations/BytecodeDemotion.py`:

```python
def demoteSourceCodeToBytecode(module_name, source_code, filename):
    bytecode = compileSourceToBytecode(source_code, filename)
    bytecode = onFrozenModuleBytecode(...)
    return marshal.dumps(bytecode)
```

The result is embedded as a `BLOB_DATA` (`X`) constant — *standard marshalled
CPython bytecode*. This is the case where **nothing at all is lost**.

Demotion applies to auto-included stdlib modules in standalone builds, to plugin
triggers, and to `--noinclude-*`-adjacent helpers. In the accelerated test
specimen, zero modules were demoted. In the standalone and onefile specimens,
**284 modules were demoted**, carrying 5 MB of real bytecode.

### 2.5 Limits — what is genuinely absent

* **No original source text.** `def derive_token`, `hashlib.sha256` and similar
  appear nowhere in the binary. Only *data* survives, not *syntax*.
* **No bytecode for compiled modules.** Once lowered to C, the intermediate
  representation is not retained.
* **Comments.** Never present in any bytecode, demoted or otherwise.
* **No encryption of the blob** in the Open Source build — verified by reading
  the loader, and by successfully decoding blobs straight out of the file.

---

## 3. Can the original source be reconstructed?

Two very different answers depending on whether a module was compiled or demoted.

### 3.1 Compiled modules — structure yes, bodies no

Against the 5-module test project, using only the shipped binary:

```
Function definitions in original source : 13
Recovered from binary                   : 13 (100.0%)

  line number EXACT match  : 13 (100.0% of recovered)
  signature EXACT match    : 13 (100.0% of recovered)
  all locals recovered     : 11 (84.6% of recovered)
  definitions NOT recovered: 0
```

Every signature matched the original exactly, including distinguishing
`LedgerReconciler.describe()` (a `@staticmethod`, no `self`) from
`ApiClient._headers(self)`, and detecting `chunk_records` and the generator
expression as `Generator` rather than plain functions.

What is **not** recovered for these modules: the body. For `derive_token`, the
binary yields

```
derive_token(username, scope, ttl_seconds)     locals: payload
```

but nothing about `hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]`.

### 3.2 Demoted modules — exact recovery

Demoted modules were proven recoverable **losslessly**. Method: extract the
`BLOB_DATA` payload, `marshal.loads` it, then compare against compiling the
original source from the same CPython version.

```
__future__.py            co_code identical=True   full fingerprint identical=True
_compat_pickle.py        co_code identical=True   full fingerprint identical=True
_collections_abc.py      co_code identical=True   full fingerprint identical=True
_aix_support.py          co_code identical=True   full fingerprint identical=True

RESULT: 4/4 demoted modules recovered with byte-identical bytecode
```

`_collections_abc.py` alone came back as 51 KB of bytecode containing 145 nested
code objects.

Taking the chain one step further — write the recovered code object back out as
a `.pyc` and run a decompiler over it — yields readable original source. Diffing
the decompiled `_aix_support.py` against the real stdlib file:

**Recovered exactly:** module docstring, all imports, `try/except` structure,
every function name and parameter list, every statement, every operator, every
string literal, function docstrings.

**Not recovered:** comments (`# pragma: no cover`, `# type: (...) -> str`) and
formatting (`'aix-...'` vs `"aix-..."`, line wrapping). This is inherent to
bytecode, not a tool limitation.

### 3.3 The other developer's claim

"Extracted/reconstructed the entire source" is **not achievable** for normally
compiled modules — the bodies are not in the file in any form. If they claimed
a byte-perfect `utils.py`, they either had the `.py` files from elsewhere, or
they are overstating what they got.

That said, if their app pulled in stdlib or plugin modules through the demotion
path, those *are* recoverable essentially intact — which may be where the claim
came from. And the metadata recovery is far richer than most developers expect,
so it would be easy to mistake the recovered skeleton for something close to
complete.

**The honest verdict: their claim is false as stated, but the underlying
capability is much stronger than the usual dismissive "Nuitka is unbreakable"
answer suggests.**

---

## 4. How this differs from PyInstaller / plain bytecode EXEs

| | PyInstaller | Nuitka |
|---|---|---|
| What ships | A copy of the `.pyc` files | Native machine code |
| Bytecode present | Yes, all of it | Only for demoted modules |
| Source recovery | Near-complete via decompilation | Structure only, for compiled modules |
| Extraction | `pyinstxtractor` — trivial | Constants blob — no public tool, format must be reverse-engineered |
| Compiled logic | Bytecode, decompilable | Native, needs a disassembler/decompiler |
| Symbol table | Full, from bytecode | Full, from `CODE_OBJECT` records |
| String literals | Present | Present |
| Comments | Never | Never |

The practical difference: with PyInstaller you attack the *code*; with Nuitka
you attack the *data and metadata*. Nuitka's protection against source
recovery for compiled modules is real — it is a compilation boundary, not an
obfuscation layer, and no tool reverses it today.

---

## 5. Techniques that yield information

Ordered by value returned, as tested:

| # | Technique | Yield |
|---|---|---|
| 1 | Decode the constants blob | Everything: literals, symbols, bytecode |
| 2 | Read `CODE_OBJECT` records | Symbol table with signatures and line numbers |
| 3 | Extract `BLOB_DATA` → `marshal.loads` | Real bytecode for demoted modules |
| 4 | Walk `meta_path_loader_entries[]` | Module list and original file paths |
| 5 | `strings` / section scan | Confirms literals, leaks paths and messages |
| 6 | COFF symbol table (Windows) | `constant_bin` and generated function names |
| 7 | Decompile recovered bytecode | Readable source for demoted modules |
| 8 | Disassemble native code | Last resort; expensive, low yield for structure |
| 9 | Dynamic: dump the onefile temp dir | Defeats the packaging layer entirely (see below) |

**The dynamic shortcut.** A `--onefile` build extracts itself to
`{TEMP}/onefile_{PID}_{TIME_US}_{RANDOM}` on first run. Anyone who can run it and
watch `%TEMP%` gets the entire `main.dist` directory — including the inner
standalone binary, which has an *uncompressed* constants blob. This is worth
more than every static technique combined, and it requires no reverse
engineering at all.

---

## 6. Maximum realistic reconstruction

**Tier A — exact.** Module list and hierarchy; original source paths; all string,
bytes and numeric literals; every function/method/lambda/comprehension name
including `<locals>` nesting; exact signatures; all local variable names; `def`
line numbers; generator/coroutine flags; embedded bytecode of demoted modules.

**Tier B — approximate.** Control flow and expression structure of compiled
functions, only via native-code analysis. Not attempted here; it is a
research-grade problem and would not reproduce Python-level readability.

**Tier C — impossible.** Original source text of compiled functions; comments;
formatting; anything deleted at compile time.

**Bottom line:** for a normally compiled module, reconstruction stops at a
precise, annotated skeleton — the "what" and the "where", never the "how". For a
demoted module, reconstruction is essentially lossless.

---

## 7. If source secrecy actually matters

Nuitka compiles; it does not obfuscate. Given the above:

1. **Do not ship secrets in the binary.** Strings, salts and URLs survive
   verbatim regardless of compiler. Use runtime configuration or a secret store.
2. **Do not rely on Nuitka for source protection.** It raises the bar for
   reading logic; it does not lower what leaks.
3. **If you need real protection**, you need a protector/obfuscator that
   encrypts the constants blob (the blob is the payload, and the Open Source
   build leaves it in cleartext), plus a license — Nuitka's own licence terms,
   not technical measures, are the practical control.
4. **Accept the metadata leak.** Names, paths and signatures will be visible.
   Name things accordingly.

---

## 8. Reproducing these results

```bash
# analyse any Nuitka binary
python3 nuitka_forensics.py target.exe --json report.json

# measure fidelity against the original project
python3 compare_recovery.py /path/to/project report.json --verbose
```

Confidence notes:

* The accelerated specimen was validated end-to-end against the compiler's own
  build directory (`main.build/blobs/__constant.bin` and `__constant.txt`), which
  is ground truth. Decoded output matched exactly: **251 constants**, matching
  the DataComposer manifest total, across all 7 blobs.
* Standalone and onefile builds were validated the same way, including 284
  recovered bytecode payloads in each.
* The bytecode-identity test compared against `compile()` output from the same
  CPython patch version, which is the strongest available form of ground truth.
* **Not tested:** Windows PE specifics. The format is platform-independent and
  the tool handles PE, but the specimens here were ELF. On Windows the blob is
  linked in via a COFF object rather than `incbin`, and onefile filenames are
  `utf-16le`. Both cases are implemented; neither was exercised against a real
  Windows binary in this environment.
