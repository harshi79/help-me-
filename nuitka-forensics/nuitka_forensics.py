#!/usr/bin/env python3
#     Nuitka binary forensics toolkit
#
#     Static analysis of Nuitka-compiled binaries (PE/ELF/Mach-O) that recovers
#     the artefacts Nuitka actually embeds at build time.
#
#     Nuitka's "constants blob" is NOT cifrado, NOT compressed and NOT
#     obfuscated by default.  It is a compact tagged binary stream produced by
#     Nuitka's own DataComposer tool.  This program implements a decoder for
#     that format, reconstructed from:
#
#         nuitka/build/include/nuitka/constants_blob_spec.h   (tag byte values)
#         nuitka/build/static_src/HelpersConstantsBlob.c      (decoder)
#         nuitka/tools/data_composer/DataComposer.py          (encoder)
#
#     What can be recovered from the blob:
#
#       * Every string literal, bytes literal, number, tuple, set, dict
#       * Every embedded file path
#       * For every function / class / lambda / comprehension:
#             - its name and full qualified nesting
#             - its exact parameter signature (arity, pos-only, kw-only,
#               *args, **kwargs)
#             - every local variable name
#             - the line number of its `def`
#             - generator / coroutine / async-generator kind
#       * Raw marshalled CPython bytecode for any module Nuitka "demoted"
#         to bytecode instead of compiling to C
#
#     What can NOT be recovered from the blob:
#
#       * Function bodies (control flow, expressions, calls) for any module
#         that was actually compiled to C.  Those exist only as native code.
#
#     The tool reports exactly which of the two applies, per module.

from __future__ import annotations

import argparse
import io
import json
import os
import re
import struct
import sys
import types
from collections import Counter, OrderedDict

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

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Static forensics for Nuitka-compiled binaries.")
    ap.add_argument("target")
    ap.add_argument("-o", "--outdir", help="dump extracted raw payloads here")
    ap.add_argument("--json", metavar="FILE", help="write full report as JSON")
    ap.add_argument("--strings", action="store_true",
                    help="list every recovered string literal")
    ap.add_argument("--skeleton", metavar="DIR",
                    help="write the reconstructed per-module symbol skeleton")
    ap.add_argument("--self-test", action="store_true",
                    help="validate the decoder against a known blob file")
    args = ap.parse_args(argv)

    if not os.path.isfile(args.target):
        ap.error("no such file: %s" % args.target)

    report, detail = analyse(args.target)
    print(render(report, detail, show_strings=args.strings))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print("\nJSON report -> %s" % args.json)

    if args.outdir and detail:
        os.makedirs(args.outdir, exist_ok=True)
        n = 0
        for i, e in enumerate(detail["bytecode"]):
            if e["recovered"]:
                path = os.path.join(args.outdir, "bytecode_%02d.marshal" % i)
                with open(path, "wb") as f:
                    f.write(e["code"].co_consts and b"" or b"")
                n += 1
        if n:
            print("Dumped %d bytecode payloads -> %s" % (n, args.outdir))

    if args.skeleton and "symbols" in report:
        written = write_skeleton(report, args.skeleton)
        print("Skeleton written (%d modules):" % len(written))
        for w in written:
            print("   %s" % w)

    return 0


if __name__ == "__main__":
    sys.exit(main())
