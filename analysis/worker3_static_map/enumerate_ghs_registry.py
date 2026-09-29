#!/usr/bin/env python3
"""Enumerate the custom GHS class/type registry embedded in ecomppc.exe.

The GHS 5.3.22 compiler uses a repeated 16-byte record of the form

    [registry_sentinel, name_ptr, tag_ptr, descriptor_ptr]

where the sentinel is the VA 0x00bd4990 in this exact executable.  Many
descriptor blocks begin with a pair ``(base_record_va, 0x00160000)``, which
exposes a useful primary-base relationship even though ordinary MSVC RTTI is
almost absent from compiler-internal classes.  Descriptor entries are packed
adjacently, so this tool intentionally decodes only the first pair at a given
descriptor pointer.

This script is intentionally dependency-free.  It parses enough PE32 metadata
to translate VAs through arbitrary section raw offsets instead of relying on
the convenient RVA==file-offset layout of most ecomppc.exe sections.
"""

from __future__ import annotations

import argparse
import csv
import struct
from dataclasses import dataclass
from pathlib import Path


SENTINEL_VA = 0x00BD4990
INHERIT_FLAGS = 0x00160000


@dataclass(frozen=True)
class Section:
    name: str
    rva: int
    virtual_size: int
    raw_offset: int
    raw_size: int


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe(data: bytes) -> tuple[int, list[Section]]:
    pe = u32(data, 0x3C)
    if data[pe : pe + 4] != b"PE\0\0":
        raise ValueError("not a PE image")
    coff = pe + 4
    section_count = u16(data, coff + 2)
    optional_size = u16(data, coff + 16)
    optional = coff + 20
    if u16(data, optional) != 0x10B:
        raise ValueError("expected PE32 optional header")
    image_base = u32(data, optional + 28)
    section_table = optional + optional_size
    sections: list[Section] = []
    for i in range(section_count):
        p = section_table + i * 40
        name = data[p : p + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        virtual_size, rva, raw_size, raw_offset = struct.unpack_from("<IIII", data, p + 8)
        sections.append(Section(name, rva, virtual_size, raw_offset, raw_size))
    return image_base, sections


def va_to_off(va: int, image_base: int, sections: list[Section]) -> int | None:
    rva = va - image_base
    for section in sections:
        if section.rva <= rva < section.rva + section.raw_size:
            return section.raw_offset + (rva - section.rva)
    return None


def off_to_va(off: int, image_base: int, sections: list[Section]) -> int | None:
    for section in sections:
        if section.raw_offset <= off < section.raw_offset + section.raw_size:
            return image_base + section.rva + (off - section.raw_offset)
    return None


def ascii_at(data: bytes, va: int, image_base: int, sections: list[Section]) -> str | None:
    off = va_to_off(va, image_base, sections)
    if off is None:
        return None
    end = data.find(b"\0", off, min(len(data), off + 256))
    if end < 0 or end == off:
        return None
    raw = data[off:end]
    if not all(0x20 <= c < 0x7F for c in raw):
        return None
    return raw.decode("ascii")


def category(name: str) -> str:
    low = name.lower()
    if name.startswith("std::") or name in {"type_info", "std::type_info"}:
        return "runtime/std"
    if "sched" in low:
        return "scheduler"
    if (
        "spill" in low
        or "coalesce" in low
        or low.startswith("register_")
        or low.startswith("alloc_table")
        or "register_changer" in low
    ):
        return "register-allocation"
    if name.startswith("objectdata_") or name in {"objectdata", "ObjectVisitor"}:
        return "IR/object-model"
    if any(
        key in low
        for key in (
            "alias",
            "liveness",
            "dataflow",
            "visitor",
            "optimizer",
            "optimiz",
            "vector",
            "substitut",
            "loop",
            "interblockdf",
            "copyprop",
        )
    ) or low.endswith("df"):
        return "optimizer/analysis"
    return "other"


def enumerate_records(data: bytes, image_base: int, sections: list[Section]) -> list[dict[str, object]]:
    sentinel = struct.pack("<I", SENTINEL_VA)
    records: list[dict[str, object]] = []
    pos = 0
    while True:
        off = data.find(sentinel, pos)
        if off < 0:
            break
        pos = off + 4
        if off + 16 > len(data):
            continue
        record_va = off_to_va(off, image_base, sections)
        if record_va is None:
            continue
        sentinel_va, name_va, tag_va, descriptor_va = struct.unpack_from("<IIII", data, off)
        if sentinel_va != SENTINEL_VA:
            continue
        name = ascii_at(data, name_va, image_base, sections)
        if name is None:
            continue
        records.append(
            {
                "record_va": record_va,
                "name": name,
                "tag_va": tag_va,
                "descriptor_va": descriptor_va,
            }
        )
    return records


def attach_base_links(
    data: bytes,
    image_base: int,
    sections: list[Section],
    records: list[dict[str, object]],
) -> None:
    by_va = {int(row["record_va"]): row for row in records}
    for row in records:
        desc_va = int(row["descriptor_va"])
        base: tuple[int, int, str] | None = None
        if desc_va:
            off = va_to_off(desc_va, image_base, sections)
            if off is not None and off + 8 <= len(data):
                base_va, flags = struct.unpack_from("<II", data, off)
                base_row = by_va.get(base_va)
                if base_row is not None and flags == INHERIT_FLAGS:
                    base = (base_va, flags, str(base_row["name"]))
        row["base"] = base
        row["category"] = category(str(row["name"]))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--category", help="emit only one category")
    args = parser.parse_args()

    data = args.exe.read_bytes()
    image_base, sections = parse_pe(data)
    records = enumerate_records(data, image_base, sections)
    attach_base_links(data, image_base, sections, records)
    if args.category:
        records = [r for r in records if r["category"] == args.category]

    out = args.output.open("w", newline="", encoding="utf-8") if args.output else None
    stream = out if out is not None else __import__("sys").stdout
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(
        [
            "record_va",
            "name",
            "category",
            "tag_va",
            "descriptor_va",
            "primary_base_record_va",
            "primary_base_name",
        ]
    )
    for row in records:
        base = row["base"]
        writer.writerow(
            [
                f"0x{int(row['record_va']):08x}",
                row["name"],
                row["category"],
                f"0x{int(row['tag_va']):08x}" if int(row["tag_va"]) else "",
                f"0x{int(row['descriptor_va']):08x}" if int(row["descriptor_va"]) else "",
                f"0x{base[0]:08x}" if base is not None else "",
                base[2] if base is not None else "",
            ]
        )
    if out is not None:
        out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
