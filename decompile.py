#!/usr/bin/env python3
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

# =========================================================================
# PART 1: the constants-blob decoder
#   Format reconstructed from Nuitka's own sources:
#     build/include/nuitka/constants_blob_spec.h   tag byte values
#     build/static_src/HelpersConstantsBlob.c      runtime decoder
#     tools/data_composer/DataComposer.py          build-time encoder
# =========================================================================

TOOL_VERSION = "2.0"

# ---------------------------------------------------------------------------
# Section 1: the DoComposer blob format
# ---------------------------------------------------------------------------
#
# Container layout (tools/data_composer/DataComposer.py: _writeConstantsBlob):
#
#     repeat:
#         name              NUL-terminated ASCII blob name
#         part_size         uint32 little-endian
#         part              part_size bytes
#
# Each `part` (DataComposer._writeConstantStream):
#
#     count                 uint16 little-endian
#     count values          tagged constant stream
#     0x2E                  "end of constants" marker
#
# A blob name of "" is the program-wide constant pool; any other name is the
# module it belongs to (e.g. "myapp.utils").

T_PREVIOUS = 0x70  # 'p'
T_NONE = 0x6E  # 'n'
T_TRUE = 0x74  # 't'
T_FALSE = 0x46  # 'F'
T_TUPLE = 0x54  # 'T'
T_LIST = 0x4C  # 'L'
T_DICT = 0x44  # 'D'
T_SET = 0x53  # 'S'
T_FROZENSET = 0x50  # 'P'
T_INT_SMALL_POS = 0x6C  # 'l'
T_INT_SMALL_NEG = 0x71  # 'q'
T_INT_LARGE_POS = 0x67  # 'g'
T_INT_LARGE_NEG = 0x47  # 'G'
T_INT_POS = 0x69  # 'i'   (Python 2 ints)
T_INT_NEG = 0x49  # 'I'
T_FLOAT_SPECIAL = 0x5A  # 'Z'
T_FLOAT = 0x66  # 'f'
T_TEXT_EMPTY = 0x73  # 's'
T_TEXT_SINGLE = 0x77  # 'w'
T_TEXT_UTF8_LEN = 0x76  # 'v'
T_TEXT_UTF8_ZT = 0x75  # 'u'
T_ATTR_NAME = 0x61  # 'a'
T_BYTES_LEN = 0x62  # 'b'
T_BYTES_ZT = 0x63  # 'c'
T_BYTES_SINGLE = 0x64  # 'd'
T_SLICE = 0x3A  # ':'
T_RANGE = 0x3B  # ';'
T_COMPLEX_SPECIAL = 0x4A  # 'J'
T_COMPLEX = 0x6A  # 'j'
T_BYTEARRAY = 0x42  # 'B'
T_BUILTIN_ANON = 0x4D  # 'M'
T_BUILTIN_SPECIAL = 0x51  # 'Q'
T_BLOB_DATA = 0x58  # 'X'
T_GENERIC_ALIAS = 0x41  # 'A'
T_UNION_TYPE = 0x48  # 'H'
T_BUILTIN_NAMED = 0x4F  # 'O'
T_BUILTIN_EXCEPTION = 0x45  # 'E'
T_CODE_OBJECT = 0x43  # 'C'
T_END = 0x2E  # '.'

# NUITKA_CONSTANT_BLOB_CODE_FLAG_*
F_QUALNAME = 0x00001
F_FREE_VARS = 0x00002
F_KW_ONLY = 0x00004
F_POS_ONLY = 0x00008
KIND_MASK = 0x00030
KIND_GENERATOR = 0x00010
KIND_COROUTINE = 0x00020
KIND_ASYNCGEN = 0x00030
F_OPTIMIZED = 0x00040
F_NEWLOCALS = 0x00080
F_VARARGS = 0x00100
F_VARKEYWORDS = 0x00200
F_NOFREE = 0x20000

FLOAT_SPECIALS = {
    0x00: 0.0,
    0x01: -0.0,
    0x02: float("nan"),
    0x03: float("-nan"),
    0x04: float("inf"),
    0x05: float("-inf"),
}

# Builtins._getAnonBuiltins() -> builtin_anon_values, in insertion order.
BUILTIN_ANON = [
    "ellipsis", "notimplemented", "bool", "bytearray", "bytes", "classmethod",
    "dict", "enumerate", "file", "float", "frozenset", "int", "list",
    "memoryview", "object", "property", "range", "reversed", "set", "slice",
    "staticmethod", "str", "tuple", "type", "zip", "generator",
    "builtin_function_or_method", "code", "module", "version_info",
    "GenericAlias", "UnionType",
]

BUILTIN_SPECIAL = {0: Ellipsis, 1: NotImplemented, 2: "sys.version_info"}


class ParseError(Exception):
    pass


class CodeObjectRecord(object):
    """A decoded NUITKA_CONSTANT_BLOB_TAG_CODE_OBJECT record."""

    __slots__ = (
        "name", "parent_qualname", "line_number", "var_names",
        "arg_count", "kw_only_count", "pos_only_count", "free_vars", "flags",
    )

    def __init__(self):
        self.name = "?"
        self.parent_qualname = None
        self.line_number = 0
        self.var_names = ()
        self.arg_count = 0
        self.kw_only_count = 0
        self.pos_only_count = 0
        self.free_vars = ()
        self.flags = 0

    # -- derived ---------------------------------------------------------
    @property
    def qualname(self):
        if self.parent_qualname:
            return "%s.%s" % (self.parent_qualname, self.name)
        return self.name

    @property
    def kind(self):
        k = self.flags & KIND_MASK
        if k == KIND_ASYNCGEN:
            return "Asyncgen"
        if k == KIND_COROUTINE:
            return "Coroutine"
        if k == KIND_GENERATOR:
            return "Generator"
        if self.flags & F_OPTIMIZED:
            return "Function"
        return "Module"

    @property
    def is_method(self):
        return (
            self.var_names
            and self.var_names[0] == "self"
            and self.flags & F_OPTIMIZED
        )

    def signature(self):
        """Rebuild a Python signature from arity + local variable names."""
        names = list(self.var_names)
        n = self.arg_count
        idx = 0

        params = []
        for _ in range(self.pos_only_count):
            if idx < len(names):
                params.append(names[idx])
                idx += 1
        if self.pos_only_count:
            params.append("/")
        for _ in range(max(0, n - self.pos_only_count)):
            if idx < len(names):
                params.append(names[idx])
                idx += 1
        if self.flags & F_VARARGS:
            params.append("*" + (names[idx] if idx < len(names) else "args"))
            idx += 1
        elif self.kw_only_count:
            params.append("*")
        for _ in range(self.kw_only_count):
            if idx < len(names):
                params.append(names[idx])
                idx += 1
        if self.flags & F_VARKEYWORDS:
            params.append("**" + (names[idx] if idx < len(names) else "kwargs"))

        # Whatever is left in var_names are genuine local variables.
        locals_ = names[idx + (1 if self.flags & F_VARKEYWORDS else 0):]
        return "%s(%s)" % (self.name, ", ".join(params)), locals_

    def __repr__(self):
        return "<CodeObjectRecord %s %r @%d>" % (
            self.kind, self.qualname, self.line_number,
        )


class BlobDataValue(object):
    """Raw binary payload embedded in the blob (e.g. marshalled bytecode)."""

    __slots__ = ("data", "offset")

    def __init__(self, data, offset):
        self.data = data
        self.offset = offset

    def __repr__(self):
        return "<BlobData %d bytes @0x%X>" % (len(self.data), self.offset)


class BlobReader(object):
    """Decoder for one DataComposer constants part."""

    def __init__(self, payload, base_offset=0):
        self.data = payload
        self.pos = 0
        self.base_offset = base_offset
        self.code_objects = []
        self.blob_datas = []

    # -- primitives ------------------------------------------------------
    def _byte(self):
        if self.pos >= len(self.data):
            raise ParseError("truncated")
        b = self.data[self.pos]
        self.pos += 1
        return b

    def _varint(self):
        """LEB128as used by _encodeVariableLength()."""
        result = 0
        shift = 0
        while True:
            b = self._byte()
            result |= (b & 0x7F) << shift
            if b < 128:
                return result
            shift += 7
            if shift > 70:
                raise ParseError("varint overflow")

    def _u16(self):
        if self.pos + 2 > len(self.data):
            raise ParseError("truncated u16")
        v = struct.unpack_from("<H", self.data, self.pos)[0]
        self.pos += 2
        return v

    def _f64(self):
        if self.pos + 8 > len(self.data):
            raise ParseError("truncated f64")
        v = struct.unpack_from("<d", self.data, self.pos)[0]
        self.pos += 8
        return v

    def _cstring(self):
        end = self.data.find(b"\x00", self.pos)
        if end < 0:
            raise ParseError("unterminated cstring")
        raw = self.data[self.pos:end]
        self.pos = end + 1
        return raw

    def _take(self, n):
        if self.pos + n > len(self.data):
            raise ParseError("truncated take")
        raw = self.data[self.pos:self.pos + n]
        self.pos += n
        return raw

    # -- the constant decoder -------------------------------------------
    def read_value(self, prev):
        """Read one tagged constant.  `prev` implements the 'p' back-ref."""
        tag = self._byte()

        if tag == T_PREVIOUS:
            if prev is _MISSING:
                raise ParseError("'p' with no previous value")
            return prev

        if tag == T_NONE:
            return None
        if tag == T_TRUE:
            return True
        if tag == T_FALSE:
            return False

        if tag == T_TUPLE:
            return tuple(self.read_many(self._varint()))
        if tag == T_LIST:
            return list(self.read_many(self._varint()))
        if tag == T_DICT:
            size = self._varint()
            keys = self.read_many(size)
            values = self.read_many(size)
            return dict(zip(keys, values))
        if tag in (T_SET, T_FROZENSET):
            items = self.read_many(self._varint())
            return set(items) if tag == T_SET else frozenset(items)

        if tag == T_INT_SMALL_POS:
            return self._varint()
        if tag == T_INT_SMALL_NEG:
            return -self._varint()
        if tag in (T_INT_POS, T_INT_NEG):
            v = self._varint()
            return v if tag == T_INT_POS else -v
        if tag in (T_INT_LARGE_POS, T_INT_LARGE_NEG):
            nparts = self._varint()
            value = 0
            for _ in range(nparts):
                value = (value << 31) + self._varint()
            return value if tag == T_INT_LARGE_POS else -value

        if tag == T_FLOAT:
            return self._f64()
        if tag == T_FLOAT_SPECIAL:
            return FLOAT_SPECIALS.get(self._byte(), "<unknown float special>")

        if tag == T_COMPLEX:
            return complex(self._f64(), self._f64())
        if tag == T_COMPLEX_SPECIAL:
            return complex(self.read_value(_MISSING), self.read_value(_MISSING))

        if tag == T_TEXT_EMPTY:
            return ""
        if tag == T_TEXT_SINGLE:
            return self._take(1).decode("utf-8", "surrogateescape")
        if tag == T_TEXT_UTF8_LEN:
            return self._take(self._varint()).decode("utf-8", "surrogateescape")
        if tag == T_TEXT_UTF8_ZT:
            return self._cstring().decode("utf-8", "surrogateescape")
        if tag == T_ATTR_NAME:
            return self._cstring().decode("utf-8", "surrogateescape")

        if tag == T_BYTES_SINGLE:
            return self._take(1)
        if tag == T_BYTES_LEN:
            return self._take(self._varint())
        if tag == T_BYTES_ZT:
            return self._cstring()
        if tag == T_BYTEARRAY:
            return bytearray(self._take(self._varint()))

        if tag == T_SLICE:
            return slice(
                self.read_value(_MISSING),
                self.read_value(_MISSING),
                self.read_value(_MISSING),
            )
        if tag == T_RANGE:
            return range(
                self.read_value(_MISSING),
                self.read_value(_MISSING),
                self.read_value(_MISSING),
            )

        if tag == T_BUILTIN_ANON:
            idx = self._byte()
            return "<builtin type %s>" % (
                BUILTIN_ANON[idx] if idx < len(BUILTIN_ANON) else idx
            )
        if tag == T_BUILTIN_SPECIAL:
            idx = self._byte()
            return BUILTIN_SPECIAL.get(idx, "<special %d>" % idx)
        if tag == T_BUILTIN_NAMED:
            return "<builtin %s>" % self._cstring().decode("utf-8", "replace")
        if tag == T_BUILTIN_EXCEPTION:
            return "<exception %s>" % self._cstring().decode("utf-8", "replace")

        if tag == T_BLOB_DATA:
            size = self._varint()
            start = self.pos
            raw = self._take(size)
            blob = BlobDataValue(bytes(raw), self.base_offset + start)
            self.blob_datas.append(blob)
            return blob

        if tag == T_GENERIC_ALIAS:
            return "GenericAlias(%r, %r)" % (
                self.read_value(_MISSING), self.read_value(_MISSING),
            )
        if tag == T_UNION_TYPE:
            return "Union[%r]" % (self.read_value(_MISSING),)

        if tag == T_CODE_OBJECT:
            return self._read_code_object()

        if tag == T_END:
            raise ParseError("unexpected end marker")

        raise ParseError("unknown tag 0x%02X (%r)" % (tag, chr(tag)))

    def read_many(self, count):
        out = []
        prev = _MISSING
        for _ in range(count):
            value = self.read_value(prev)
            out.append(value)
            prev = value
        return out

    def _read_code_object(self):
        rec = CodeObjectRecord()
        rec.flags = self._varint()
        rec.name = self.read_value(_MISSING)
        rec.line_number = self._varint() + 1
        varnames = self.read_value(_MISSING)
        rec.var_names = tuple(varnames) if isinstance(varnames, (tuple, list)) else ()
        rec.arg_count = self._varint()

        if rec.flags & F_QUALNAME:
            # The writer stores only the PARENT qualname (it strips the final
            # component, which is `rec.name`).
            parent = self.read_value(_MISSING)
            rec.parent_qualname = parent if isinstance(parent, str) else None
        if rec.flags & F_FREE_VARS:
            fv = self.read_value(_MISSING)
            rec.free_vars = tuple(fv) if isinstance(fv, (tuple, list)) else ()
        if rec.flags & F_KW_ONLY:
            rec.kw_only_count = self._varint() + 1
        if rec.flags & F_POS_ONLY:
            rec.pos_only_count = self._varint() + 1

        self.code_objects.append(rec)
        return rec


_MISSING = object()


class Blob(object):
    __slots__ = ("name", "size", "offset", "values", "code_objects", "blob_datas",
                 "parse_error")

    def __init__(self, name, size, offset):
        self.name = name
        self.size = size
        self.offset = offset
        self.values = []
        self.code_objects = []
        self.blob_datas = []
        self.parse_error = None


def parse_part(payload, size=None, base_offset=0):
    """Parse one constants part.  Returns (count, reader) or raises ParseError."""
    reader = BlobReader(payload, base_offset=base_offset)
    count = reader._u16()
    reader.read_many(count)
    if reader.data[reader.pos:reader.pos + 1] != bytes([T_END]):
        raise ParseError(
            "missing end marker at %d (got %r)" % (reader.pos, reader.data[reader.pos:reader.pos + 1])
        )
    reader.pos += 1

    if size is not None and reader.pos != size:
        raise ParseError("size mismatch: consumed %d of %d" % (reader.pos, size))

    return count, reader


# ---------------------------------------------------------------------------
# Section 2: locating the blob inside a binary
# ---------------------------------------------------------------------------

# Blob names are either "" (global pool), ".bytecode", or a dotted module name.
_PLAUSIBLE_NAME = re.compile(rb"^\.?[A-Za-z_][A-Za-z0-9_.]*$")


def _walk_directory(data, start, max_entries=100000):
    """Walk the DataComposer directory starting at `start`."""
    pos = start
    entries = []

    while pos < len(data) and len(entries) < max_entries:
        nul = data.find(b"\x00", pos, pos + 512)
        if nul < 0:
            break
        name = data[pos:nul]

        # A name is either empty (the global pool) or a dotted module name.
        if name and not _PLAUSIBLE_NAME.match(name):
            break
        if nul + 5 > len(data):
            break

        size = struct.unpack_from("<I", data, nul + 1)[0]
        data_start = nul + 5
        if size == 0 or data_start + size > len(data):
            break

        payload = data[data_start:data_start + size]
        blob = Blob(name.decode("ascii", "replace"), size, data_start)
        try:
            count, reader = parse_part(payload, size=size, base_offset=data_start)
            blob.values = [None] * count
            blob.code_objects = reader.code_objects
            blob.blob_datas = reader.blob_datas
            # Re-read into a flat list for reporting.
            r2 = BlobReader(payload, base_offset=data_start)
            r2._u16()
            blob.values = r2.read_many(count)
        except ParseError as exc:
            blob.parse_error = str(exc)

        entries.append(blob)
        pos = data_start + size

    return entries


# ---------------------------------------------------------------------------
# Section 2b: onefile (self-extracting) payload
# ---------------------------------------------------------------------------
#
# A --onefile build is:  <inner binary> + "KA" + indicator + <payload> + u64 size
#
# The trailing little-endian u64 gives the payload length, so the payload can
# be located directly from the end of the file.  Format per
# nuitka/tools/onefile_compressor/OnefileCompressor.py:
#
#     entry:
#         filename (utf-16le on Windows, utf8 elsewhere) + "\0"
#         [POSIX only] flags u8   bit0 = executable, bit1 = symlink
#         if symlink:  target + "\0"
#         else:        u64 original_size
#                      [u32 crc32]            when file checksums are on (default)
#                      [u32 compressed_size]  only in --onefile-as-archive mode
#                      data
#     terminator:  empty filename
#
# Default (non-archive) mode compresses the whole payload as ONE zstd stream.

ONEFILE_MAGIC = b"KA"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def find_onefile_payload(data):
    """Return (indicator, payload_offset, payload_bytes) or None.

    Two layouts exist across Nuitka versions:

      A) older: payload appended, followed by a trailing u64 giving its length
      B) newer: payload linked in as a blob, so the offset must be discovered

    Layout B is detected by the strong signature "KA" + indicator byte, and,
    for compressed payloads, a zstd frame starting immediately after.
    """
    # ---- layout A: trailing size field ---------------------------------
    if len(data) >= 16:
        size = struct.unpack_from("<Q", data, len(data) - 8)[0]
        if 0 < size <= len(data) - 8:
            start = len(data) - 8 - size
            if start >= 0 and data[start:start + 2] == ONEFILE_MAGIC:
                ind = data[start + 2:start + 3]
                if ind in (b"Y", b"N"):
                    return ind, start, data[start + 3:len(data) - 8]

    # ---- layout B: embedded blob, locate by signature ------------------
    pos = 0
    while True:
        pos = data.find(ONEFILE_MAGIC, pos)
        if pos < 0:
            return None
        ind = data[pos + 2:pos + 3]

        if ind == b"Y" and data[pos + 3:pos + 7] == ZSTD_MAGIC:
            # Stream runs to end of file; the zstd frame is self-terminating.
            return ind, pos, data[pos + 3:]

        if ind == b"N":
            # Uncompressed: require the next bytes to look like an entry,
            # i.e. a plausible NUL-terminated filename.
            nxt = data[pos + 3:pos + 3 + 64]
            if b"\x00" in nxt and all(32 <= c < 127 for c in nxt.split(b"\x00")[0] or b"x"):
                return ind, pos, data[pos + 3:]

        pos += 1


def _zstd_decompress(blob, expected_hint=0):
    try:
        import zstandard
    except ImportError:
        raise RuntimeError(
            "zstandard module required to unpack a compressed onefile payload. "
            "Install with: pip install zstandard"
        )

    # decompressobj() is used rather than stream_reader(): the payload frame
    # frequently has no recorded content size, which stream_reader() rejects.
    # decompressobj() consumes exactly the first frame and ignores anything
    # that follows it.
    dctx = zstandard.ZstdDecompressor()
    return dctx.decompressobj().decompress(blob)


def parse_onefile_payload(payload, indicator, is_windows=None):
    """Parse the payload into {relative_path: bytes}.

    Handles both default single-stream mode and --onefile-as-archive mode, and
    auto-detects the Windows vs POSIX entry layout.
    """
    if indicator == b"Y":
        try:
            payload = _zstd_decompress(payload)
        except Exception as exc:
            return None, "payload decompression failed: %s" % exc

    results = {}
    # Try the plausible layout combinations.
    for enc, win, has_crc, archive in (
        ("utf-16le", True, True, False),
        ("utf-16le", True, False, False),
        ("utf-8", False, True, False),
        ("utf-8", False, False, False),
        ("utf-16le", True, True, True),
        ("utf-16le", True, False, True),
        ("utf-8", False, True, True),
        ("utf-8", False, False, True),
    ):
        if is_windows is not None and win != is_windows:
            continue
        got = _try_parse_entries(payload, enc, win, has_crc, archive)
        if got is not None:
            return got, None

    return None, "could not parse payload entries in any known layout"


def _try_parse_entries(payload, enc, win, has_crc, archive):
    pos = 0
    out = {}
    n = len(payload)

    while pos < n:
        term = ("\0").encode(enc)
        end = payload.find(term, pos)
        if end < 0:
            return None
        # utf-16le terminator is two bytes; a lone byte can also match.
        try:
            name = payload[pos:end].decode(enc)
        except UnicodeDecodeError:
            return None
        pos = end + len(term)

        if name == "":
            return out if out else None
        if name.count("\x00") or len(name) > 512:
            return None

        if not win:
            if pos >= n:
                return None
            flags = payload[pos]
            pos += 1
            if flags & 2:
                lt = payload.find(term, pos)
                if lt < 0:
                    return None
                pos = lt + len(term)
                out[name] = None  # symlink marker
                continue

        if pos + 8 > n:
            return None
        orig = struct.unpack_from("<Q", payload, pos)[0]
        pos += 8

        if has_crc:
            if pos + 4 > n:
                return None
            pos += 4

        size = orig
        if archive:
            if pos + 4 > n:
                return None
            size = struct.unpack_from("<I", payload, pos)[0]
            pos += 4

        if orig > (1 << 33) or pos + size > n:
            return None
        out[name] = payload[pos:pos + size]
        pos += size

    return out if out else None


def load_blobs(path):
    """Locate constants blobs in a binary, transparently handling onefile.

    Returns (blobs, meta) where meta describes any packaging layer that had to
    be unwrapped.  Used by both the reporter and the reconstructor so the two
    always agree on what the target contains.
    """
    data = open(path, "rb").read()
    meta = {}

    off, blobs = find_blobs(data)
    if off is not None:
        meta["packaging"] = "direct"
        return blobs, meta

    of = find_onefile_payload(data)
    if of is None:
        return None, meta

    indicator, payload_off, payload = of
    meta["packaging"] = "onefile"
    meta["onefile_payload_offset"] = payload_off
    meta["onefile_compressed"] = indicator == b"Y"

    files, err = parse_onefile_payload(payload, indicator)
    if files is None:
        meta["onefile_error"] = err
        return None, meta

    meta["onefile_files"] = len(files)
    cands = [(n, d) for n, d in files.items() if d and d[:2] in (b"MZ", b"\x7fE")]
    cands.sort(key=lambda kv: (b".bytecode\x00" not in kv[1], -len(kv[1])))
    for name, inner in cands:
        inner_off, inner_blobs = find_blobs(inner)
        if inner_off is not None:
            meta["onefile_inner"] = name
            return inner_blobs, meta

    return None, meta


def find_blobs(data):
    """Locate the constants blob directory within the image.

    Primary anchor: ".bytecode", which DataComposer always emits first.
    """
    if b".bytecode\x00" not in data:
        return None, []

    best = None
    search_from = 0
    while True:
        idx = data.find(b".bytecode\x00", search_from)
        if idx < 0:
            break
        search_from = idx + 1
        entries = _walk_directory(data, idx)
        if not entries:
            continue
        good = sum(1 for e in entries if e.parse_error is None)
        if best is None or good > best[0]:
            best = (good, idx, entries)

    if best is None:
        return None, []

    return best[1], best[2]


# ---------------------------------------------------------------------------
# Section 3: container identification
# ---------------------------------------------------------------------------

PE_MACHINE = {0x014C: "i386", 0x8664: "x86_64", 0xAA64: "arm64"}


def identify(path):
    with open(path, "rb") as f:
        data = f.read()
    head = data[:0x40]
    info = {"path": os.path.abspath(path), "size": len(data), "raw": data}

    if head[:2] == b"MZ":
        info["format"] = "PE (Windows)"
        e = struct.unpack_from("<I", data, 0x3C)[0]
        if data[e:e + 4] == b"PE\0\0":
            machine, nsec, ts, _, _, optsize, chars = struct.unpack_from(
                "<HHIIIHH", data, e + 4)
            info["machine"] = PE_MACHINE.get(machine, hex(machine))
            info["section_count"] = nsec
            info["timestamp"] = ts
            info["is_dll"] = bool(chars & 0x2000)
            magic = struct.unpack_from("<H", data, e + 24)[0]
            info["pe_magic"] = {0x10B: "PE32", 0x20B: "PE32+"}.get(magic, "?")
            info["subsystem"] = {2: "GUI", 3: "console"}.get(
                struct.unpack_from("<H", data, e + 24 + 68)[0], "?")
            sec = []
            base = e + 24 + optsize
            for i in range(nsec):
                off = base + i * 40
                nm = data[off:off + 8].rstrip(b"\0").decode("latin-1")
                vs, va, rs, rp = struct.unpack_from("<IIII", data, off + 8)
                sec.append({"name": nm, "vaddr": va, "raw_offset": rp, "raw_size": rs})
            info["sections"] = sec
        return info

    if head[:4] == b"\x7fELF":
        info["format"] = "ELF"
        info["machine"] = {0x3E: "x86_64", 0x03: "i386", 0xB7: "aarch64"}.get(
            struct.unpack_from("<H", head, 18)[0], "?")
        info["pe_magic"] = "n/a"
        return info

    info["format"] = "unknown"
    return info


def detect_nuitka(data):
    markers = [
        (b"__nuitka_version__", "dunder marker __nuitka_version__"),
        (b"NUITKA_CONSTANT_BLOB", "constants blob symbol"),
        (b"nuitka_module_loader", "meta-path loader class"),
        (b"Nuitka_MetaPathBasedLoaderEntry", "meta-path loader table"),
        (b"loadConstantsBlob", "constants blob loader"),
        (b"_unpackBlobConstant", "constants blob decoder"),
        (b"constants_blob_spec.h", "blob format header"),
        (b"__compiled__", "dunder __compiled__"),
        (b"Nuitka_", "Nuitka runtime symbols"),
        (b"NUITKA_ONEFILE", "onefile bootstrap definitions"),
        (b"onefile_", "onefile bootstrap"),
        (b"KA", None),
    ]
    found = [label for needle, label in markers if label and needle in data]

    versions = sorted(set(
        m.group(0).decode() for m in
        re.finditer(rb"\b[0-9]+\.[0-9]+\.[0-9]+[A-Za-z0-9.\-]*\b", data)
    ))
    return {"is_nuitka": bool(found), "markers": found, "version_like": versions[:120]}


# ---------------------------------------------------------------------------
# Section 4: bytecode recovery
# ---------------------------------------------------------------------------

def try_marshal(raw):
    """Nuitka demotes some modules to bytecode; that payload is marshal'd."""
    for off in range(0, min(24, len(raw))):
        try:
            code = _loads(raw[off:])
        except Exception:
            continue
        if isinstance(code, types.CodeType):
            return off, code
    return None


def _loads(raw):
    import marshal
    return marshal.loads(raw)


def count_code_objects(code):
    total = 1
    for c in code.co_consts:
        if isinstance(c, types.CodeType):
            total += count_code_objects(c)
    return total


# ---------------------------------------------------------------------------
# Section 5: analysis driver
# ---------------------------------------------------------------------------

def analyse(path):
    info = identify(path)
    data = info.pop("raw")

    report = OrderedDict()
    report["input"] = info
    report["nuitka"] = detect_nuitka(data)

    start, blobs = find_blobs(data)
    if start is None:
        # Possibly a onefile (self-extracting) build: unpack and recurse into
        # the inner standalone binary, which does carry the constants blob.
        of = find_onefile_payload(data)
        if of is not None:
            indicator, off, payload = of
            report["onefile"] = {
                "detected": True,
                "payload_offset": off,
                "payload_bytes": len(payload),
                "compressed": indicator == b"Y",
            }
            files, err = parse_onefile_payload(payload, indicator)
            if files is None:
                report["onefile"]["error"] = err
            else:
                report["onefile"]["file_count"] = len(files)
                report["onefile"]["files"] = sorted(files.keys())[:200]
                # Several entries are PE/ELF images (the start binary plus any
                # bundled shared libraries).  The one we want is simply the one
                # that actually carries the constants blob.
                cands = [
                    (n, d) for n, d in files.items()
                    if d and d[:2] in (b"MZ", b"\x7fE")
                ]
                cands.sort(key=lambda kv: (b".bytecode\x00" not in kv[1], -len(kv[1])))
                for inner_name, inner in cands:
                    inner_off, inner_blobs = find_blobs(inner)
                    if inner_off is None:
                        continue
                    report["onefile"]["inner_binary"] = inner_name
                    report["onefile"]["inner_bytes"] = len(inner)
                    report["onefile"]["inner_blob_offset"] = inner_off
                    start, blobs = inner_off, inner_blobs
                    break
        if start is None:
            report["blob"] = {"found": False}
            return report, None

    total_constants = 0
    strings = set()
    numbers = set()
    blob_datas = []
    modules = []

    for blob in blobs:
        total_constants += len(blob.values)
        _collect_strings(blob.values, strings, numbers)
        blob_datas.extend(blob.blob_datas)
        modules.append({
            "name": blob.name or "<global pool>",
            "size": blob.size,
            "constants": len(blob.values),
            "code_objects": len(blob.code_objects),
            "parse_error": blob.parse_error,
        })

    report["blob"] = {
        "found": True,
        "offset": start,
        "blob_count": len(blobs),
        "total_constants": total_constants,
        "blob_size_total": sum(b.size for b in blobs),
    }
    report["modules"] = modules
    report["string_count"] = len(strings)
    report["number_count"] = len(numbers)

    # ---- symbols, per module ------------------------------------------
    #
    # The 'C' record stores only the *class-level* parent scope.  The precise
    # Python qualname, including the "<locals>" chain that distinguishes a
    # nested closure from a method, is kept separately as a string constant in
    # the same module blob (it is needed for the function's __qualname__).
    # We pair the two so the reported qualname is the real one.
    symbols = OrderedDict()
    for blob in blobs:
        qualname_pool = [
            v for v in _walk_strings(blob.values)
            if "<locals>" in v and len(v) < 400
        ]
        recs = []
        for rec in blob.code_objects:
            sig, locals_ = rec.signature()
            qn = rec.qualname
            exact = _match_qualname(qualname_pool, rec.name)
            if exact:
                qn = exact
            recs.append({
                "line": rec.line_number,
                "kind": rec.kind,
                "qualname": qn,
                "scope": rec.parent_qualname,
                "signature": sig,
                "locals": locals_,
                "freevars": list(rec.free_vars),
                "varargs": bool(rec.flags & F_VARARGS),
                "kwargs": bool(rec.flags & F_VARKEYWORDS),
            })
        recs.sort(key=lambda r: (r["line"], r["qualname"] or ""))
        symbols[blob.name or "<global pool>"] = recs

    report["symbols"] = symbols
    report["total_code_objects"] = sum(len(v) for v in symbols.values())

    # ---- embedded bytecode --------------------------------------------
    bc = []
    for bd in blob_datas:
        got = try_marshal(bd.data)
        entry = {"size": len(bd.data), "offset": bd.offset, "recovered": got is not None}
        if got:
            off, code = got
            entry.update({
                "marshal_offset": off,
                "co_filename": code.co_filename,
                "co_name": code.co_name,
                "co_names": list(code.co_names),
                "nested_code_objects": count_code_objects(code),
                "code": code,
            })
        bc.append(entry)
    report["embedded_bytecode"] = [
        {k: v for k, v in e.items() if k != "code"} for e in bc
    ]

    # ---- paths ---------------------------------------------------------
    report["paths"] = _extract_paths(data)

    return report, {
        "strings": strings, "numbers": numbers,
        "bytecode": bc, "blobs": blobs, "data": data,
    }


def _walk_strings(values):
    """Yield every string found anywhere in a nested constant structure."""
    stack = list(values)
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            yield v
        elif isinstance(v, (tuple, list, set, frozenset)):
            stack.extend(v)
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())


def _match_qualname(pool, name):
    """Find the precise qualname for a nested definition.

    Nuitka flattens the parent scope in the code-object record, so a closure
    `_normalise` inside `LedgerReconciler.add_entry` is recorded with parent
    "LedgerReconciler".  The real qualname is
    "LedgerReconciler.add_entry.<locals>._normalise" and survives as a string.
    """
    suffix = "<locals>." + name
    hits = sorted({q for q in pool if q.endswith(suffix)}, key=len)
    if len(hits) == 1:
        return hits[0]
    if hits:
        # Ambiguous by name alone; report the shortest deterministic choice and
        # let the caller see the alternatives in the raw strings dump.
        return hits[0]
    return None


def _collect_strings(values, strings, numbers):
    stack = list(values)
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            if 2 <= len(v) <= 4000:
                strings.add(v)
        elif isinstance(v, bytes):
            try:
                s = v.decode("utf-8")
                if 3 <= len(s) <= 4000:
                    strings.add(s)
            except UnicodeDecodeError:
                pass
        elif isinstance(v, (int, float)) and not isinstance(v, bool):
            numbers.add(v)
        elif isinstance(v, (tuple, list, set, frozenset)):
            stack.extend(v)
        elif isinstance(v, dict):
            stack.extend(v.keys())
            stack.extend(v.values())


_PATH_RE = re.compile(
    rb"(?:[A-Za-z]:\\\\?[^\x00\"'<>|\r\n]{3,240}"
    rb"|/(?:home|Users|root|opt|srv|var|tmp|app|usr)[^\x00\"'<>|\r\n]{3,240})"
)


def _extract_paths(data):
    out = set()
    for m in _PATH_RE.finditer(data):
        try:
            out.add(m.group(0).decode("utf-8"))
        except UnicodeDecodeError:
            out.add(m.group(0).decode("latin-1", "replace"))
    return sorted(out)[:200]


# ---------------------------------------------------------------------------
# Section 6: rendering
# ---------------------------------------------------------------------------

W = 78


def render(report, detail=None, show_strings=False):
    o = []
    p = o.append

    inp = report["input"]
    p("=" * W)
    p("NUITKA BINARY FORENSICS REPORT")
    p("=" * W)
    p("")
    p("File          : %s" % inp["path"])
    p("Size          : %d bytes (%.2f MB)" % (inp["size"], inp["size"] / 1048576))
    p("Container     : %s" % inp.get("format"))
    if inp.get("machine"):
        p("Architecture  : %s" % inp["machine"])
    if inp.get("format", "").startswith("PE"):
        p("PE type       : %s / %s subsystem" % (inp.get("pe_magic"), inp.get("subsystem")))
        p("Sections      : %d" % inp.get("section_count", 0))
    p("")

    nk = report["nuitka"]
    p("-" * W)
    p("1. BUILD IDENTIFICATION")
    p("-" * W)
    p("Nuitka detected : %s" % ("YES" if nk["is_nuitka"] else "NO"))
    for m in nk["markers"]:
        p("   - %s" % m)
    p("")

    b = report["blob"]
    p("-" * W)
    p("2. CONSTANTS BLOB")
    p("-" * W)

    of = report.get("onefile")
    if of and of.get("detected"):
        p("ONEFILE (self-extracting) build detected.")
        p("   payload offset : 0x%X" % of["payload_offset"])
        p("   payload bytes  : %d" % of["payload_bytes"])
        p("   compressed     : %s" % ("yes (zstd)" if of["compressed"] else "no"))
        if of.get("error"):
            p("   ERROR          : %s" % of["error"])
        if of.get("file_count"):
            p("   files in payload: %d" % of["file_count"])
        if of.get("inner_binary"):
            p("   inner binary   : %s (%d bytes)"
              % (of["inner_binary"], of["inner_bytes"]))
        if of.get("inner_blob_offset") is not None:
            p("   inner blob dir : 0x%X  <-- analysed below"
              % of["inner_blob_offset"])
        p("")

    if not b.get("found"):
        p("NOT FOUND.")
        p("")
        p("No Nuitka constants blob was located.  Likely causes:")
        p("  - packed/encrypted by a third-party protector")
        p("  - a onefile payload that could not be decompressed (needs zstandard)")
        p("  - not a Nuitka build")
        return "\n".join(o)

    p("Directory offset   : 0x%X" % b["offset"])
    p("Blobs in directory : %d" % b["blob_count"])
    p("Total constants    : %d" % b["total_constants"])
    p("Blob bytes         : %d" % b["blob_size_total"])
    p("Distinct strings   : %d" % report["string_count"])
    p("Distinct numbers   : %d" % report["number_count"])
    p("")
    p("Blob directory (this is the recovered module list):")
    for m in report["modules"]:
        note = "" if not m["parse_error"] else "   [%s]" % m["parse_error"]
        p("   %-34s %7d bytes  %5d constants  %4d code objects%s"
          % (m["name"], m["size"], m["constants"], m["code_objects"], note))
    p("")

    p("-" * W)
    p("3. RECOVERED SYMBOL TABLE (exact, from embedded code-object records)")
    p("-" * W)
    p("Total code objects recovered: %d" % report["total_code_objects"])
    p("")
    for mod, recs in report["symbols"].items():
        if not recs:
            continue
        p("  MODULE: %s   (%d code objects)" % (mod, len(recs)))
        for r in recs:
            p("     L%-6s %-10s %s" % (r["line"], r["kind"], r["signature"]))
            if r["locals"]:
                p("              locals: %s" % ", ".join(r["locals"]))
            if r["freevars"]:
                p("              closure: %s" % ", ".join(r["freevars"]))
        p("")

    p("-" * W)
    p("4. EMBEDDED RAW PAYLOADS (BlobData)")
    p("-" * W)
    if not report["embedded_bytecode"]:
        p("None present.  Every module in this build was compiled to native code,")
        p("so no CPython bytecode exists anywhere in the file.")
    for e in report["embedded_bytecode"]:
        p("   %d bytes @0x%X" % (e["size"], e["offset"]))
        if e["recovered"]:
            p("      ** MARSHALLED CPYTHON BYTECODE RECOVERED **")
            p("      co_filename: %s" % e["co_filename"])
            p("      co_name    : %s" % e["co_name"])
            p("      nested code objects: %d" % e["nested_code_objects"])
    p("")

    p("-" * W)
    p("5. EMBEDDED PATH STRINGS")
    p("-" * W)
    if not report["paths"]:
        p("None found.")
    for x in report["paths"][:40]:
        p("   %s" % x)
    if len(report["paths"]) > 40:
        p("   ... and %d more" % (len(report["paths"]) - 40))
    p("")

    if show_strings and detail:
        p("-" * W)
        p("6. ALL RECOVERED STRING LITERALS")
        p("-" * W)
        for s in sorted(detail["strings"]):
            p(repr(s))
        p("")

    return "\n".join(o)


def write_skeleton(report, outdir):
    """Write one .py file per recovered module, symbols exact, bodies marked."""
    os.makedirs(outdir, exist_ok=True)
    written = []

    for mod, recs in report["symbols"].items():
        if not recs:
            continue
        fname = "<global_pool>" if mod.startswith("<") else mod
        target = os.path.join(outdir, fname.replace(".", "/") + ".py")
        os.makedirs(os.path.dirname(target), exist_ok=True)

        lines = [
            "# Reconstructed from a Nuitka binary by static analysis.",
            "# Module: %s" % mod,
            "#",
            "# Recovered EXACTLY from embedded code-object records:",
            "#   - every function/class/lambda name and its nesting",
            "#   - every parameter list and argument kind",
            "#   - every local variable name",
            "#   - the source line number of each definition",
            "#",
            "# NOT recovered: function bodies.  This module was compiled to native",
            "# code, so its statements exist only as machine code.  Bodies below",
            "# are placeholders, not reconstructions.",
            "",
        ]
        for r in recs:
            lines.append("")
            lines.append("# line %s" % r["line"])
            lines.append("def %s:" % r["signature"])
            lines.append("    # NOT RECOVERED (compiled to native code)")
            lines.append("    raise NotImplementedError")
        lines.append("")

        with open(target, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        written.append(target)

    return written


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


# =========================================================================
# PART 2: per-function evidence extraction
# =========================================================================

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
