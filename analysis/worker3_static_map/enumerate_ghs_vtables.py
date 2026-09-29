#!/usr/bin/env python3
"""Find high-confidence GHS custom vtables associated with class records.

For ecomppc.exe the useful custom tables have this shape in data:

    0x00000000
    class_record_va
    this_adjust_0
    code_pointer_0
    this_adjust_1
    code_pointer_1
    ...

The object's vptr points at the first ``(this_adjust, code_pointer)`` pair.
This scanner requires at least two consecutive executable slots to suppress
ordinary references to class records.
"""

from __future__ import annotations

import argparse
import csv
import struct
from pathlib import Path

from enumerate_ghs_registry import enumerate_records, off_to_va, parse_pe, va_to_off


def s32(value: int) -> int:
    return struct.unpack("<i", struct.pack("<I", value))[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("exe", type=Path)
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--min-slots", type=int, default=2)
    parser.add_argument("--max-slots", type=int, default=512)
    args = parser.parse_args()

    data = args.exe.read_bytes()
    image_base, sections = parse_pe(data)
    text = next(s for s in sections if s.name == ".text")
    text_lo = image_base + text.rva
    text_hi = text_lo + max(text.virtual_size, text.raw_size)
    records = enumerate_records(data, image_base, sections)

    rows: list[tuple[int, str, int, int, list[tuple[int, int]]]] = []
    for record in records:
        record_va = int(record["record_va"])
        needle = struct.pack("<I", record_va)
        pos = 0
        while True:
            ref_off = data.find(needle, pos)
            if ref_off < 0:
                break
            pos = ref_off + 4
            if ref_off < 4 or ref_off + 20 > len(data):
                continue
            # GHS custom tables observed in this binary have a zero word before
            # the class-record pointer.
            if struct.unpack_from("<I", data, ref_off - 4)[0] != 0:
                continue
            slots: list[tuple[int, int]] = []
            p = ref_off + 4
            for _ in range(args.max_slots):
                if p + 8 > len(data):
                    break
                adjust_u, code_va = struct.unpack_from("<II", data, p)
                adjust = s32(adjust_u)
                if not (-0x10000 <= adjust <= 0x10000 and text_lo <= code_va < text_hi):
                    break
                slots.append((adjust, code_va))
                p += 8
            if len(slots) < args.min_slots:
                continue
            header_va = off_to_va(ref_off - 4, image_base, sections)
            vptr_va = off_to_va(ref_off + 4, image_base, sections)
            if header_va is None or vptr_va is None:
                continue
            rows.append((record_va, str(record["name"]), header_va, vptr_va, slots))

    rows.sort(key=lambda row: (row[0], row[2]))
    out = args.output.open("w", newline="", encoding="utf-8") if args.output else None
    stream = out if out is not None else __import__("sys").stdout
    writer = csv.writer(stream, delimiter="\t", lineterminator="\n")
    writer.writerow(
        ["record_va", "name", "table_header_va", "vptr_va", "slot_count", "slots"]
    )
    for record_va, name, header_va, vptr_va, slots in rows:
        slot_text = ",".join(f"{adjust:+d}:0x{code_va:08x}" for adjust, code_va in slots)
        writer.writerow(
            [
                f"0x{record_va:08x}",
                name,
                f"0x{header_va:08x}",
                f"0x{vptr_va:08x}",
                len(slots),
                slot_text,
            ]
        )
    if out is not None:
        out.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
