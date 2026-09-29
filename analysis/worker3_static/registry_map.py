#!/usr/bin/env python3
"""Decode GHS ecomppc custom scheduler class-registration records.

The compiler's own scheduler/resource-model classes are not represented by
ordinary MSVC RTTI.  Instead, their names participate in a compact 16-byte
registration record.  For the scheduler families this script recovers:

    +0x00  shared registry pointer
    +0x04  class-name pointer
    +0x08  runtime token/global pointer
    +0x0c  descriptor pointer (or zero for a root)

The descriptor starts with a pointer to the base class's registration record,
followed by a flags/offset word.  Other data tables contain pointers back to
the registration record followed by alternating callback pointer / zero words;
those are emitted as callback tables and annotated with Ghidra function names
when functions.tsv is supplied.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import struct
from pathlib import Path


TARGET_NAMES = (
    "g4_resource_scheduler",
    "ppc970_resource_scheduler",
    "ame_resource_scheduler",
    "list_scheduler",
    "resource_model_scheduler",
    "compat_list_scheduler",
    "ls_window_scheduler",
    "ws_interface",
)


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def parse_pe(data: bytes):
    pe = u32(data, 0x3C)
    if data[pe:pe + 4] != b"PE\0\0":
        raise SystemExit("not a PE file")
    coff = pe + 4
    nsec = u16(data, coff + 2)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    if u16(data, opt) != 0x10B:
        raise SystemExit("expected PE32")
    base = u32(data, opt + 28)
    sec_table = opt + opt_size
    sections = []
    for i in range(nsec):
        off = sec_table + i * 40
        sections.append(
            {
                "name": data[off:off + 8].rstrip(b"\0").decode("ascii", "replace"),
                "virtual_size": u32(data, off + 8),
                "rva": u32(data, off + 12),
                "raw_size": u32(data, off + 16),
                "raw_offset": u32(data, off + 20),
            }
        )
    return base, sections


def make_converters(base: int, sections: list[dict]):
    def off_to_va(off: int) -> int | None:
        for s in sections:
            if s["raw_offset"] <= off < s["raw_offset"] + s["raw_size"]:
                return base + s["rva"] + off - s["raw_offset"]
        return None

    def va_to_off(va: int) -> int | None:
        rva = va - base
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["rva"] <= rva < s["rva"] + span:
                delta = rva - s["rva"]
                if delta < s["raw_size"]:
                    return s["raw_offset"] + delta
        return None

    return off_to_va, va_to_off


def load_functions(path: Path | None):
    if path is None or not path.exists():
        return [], []
    rows = []
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            rows.append(
                (
                    int(row["entry"], 16),
                    int(row["body_max"], 16),
                    row["name"],
                )
            )
    rows.sort()
    return [x[0] for x in rows], rows


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("--functions", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    ns = ap.parse_args()

    data = ns.exe.read_bytes()
    image_base, sections = parse_pe(data)
    off_to_va, va_to_off = make_converters(image_base, sections)
    text = next(s for s in sections if s["name"] == ".text")
    text_lo = image_base + text["rva"]
    text_hi = text_lo + text["virtual_size"]
    starts, functions = load_functions(ns.functions)

    def code_name(va: int) -> str | None:
        if not (text_lo <= va < text_hi) or not starts:
            return None
        i = bisect.bisect_right(starts, va) - 1
        if i < 0:
            return None
        lo, hi, name = functions[i]
        if not (lo <= va <= hi):
            return None
        return name if va == lo else f"{name}+0x{va - lo:x}"

    def ptr_refs(va: int) -> list[int]:
        needle = struct.pack("<I", va)
        refs = []
        pos = 0
        while True:
            pos = data.find(needle, pos)
            if pos < 0:
                break
            ref_va = off_to_va(pos)
            if ref_va is not None:
                refs.append(ref_va)
            pos += 1
        return refs

    records = {}
    for name in TARGET_NAMES:
        needle = name.encode("ascii") + b"\0"
        occurrences = []
        pos = 0
        while True:
            pos = data.find(needle, pos)
            if pos < 0:
                break
            prev = data[pos - 1] if pos else 0
            # Do not treat the suffix of compat_list_scheduler as the
            # standalone list_scheduler name.
            if not (chr(prev).isalnum() or prev in b"_:"):
                occurrences.append(pos)
            pos += 1

        record_va = None
        record = None
        string_va = None
        for string_off in occurrences:
            candidate_string_va = off_to_va(string_off)
            if candidate_string_va is None:
                continue
            for name_ref in ptr_refs(candidate_string_va):
                maybe = name_ref - 4
                off = va_to_off(maybe)
                if off is None or off + 16 > len(data):
                    continue
                words = [u32(data, off + i) for i in range(0, 16, 4)]
                if words[1] != candidate_string_va:
                    continue
                string_va = candidate_string_va
                record_va = maybe
                record = words
                break
            if record_va is not None:
                break
        if record_va is None or record is None:
            continue
        desc_va = record[3]
        base_record = 0
        desc_word = 0
        if desc_va:
            desc_off = va_to_off(desc_va)
            if desc_off is not None and desc_off + 8 <= len(data):
                base_record = u32(data, desc_off)
                desc_word = u32(data, desc_off + 4)
        records[name] = {
            "name": name,
            "string_va": string_va,
            "record_va": record_va,
            "registry_ptr": record[0],
            "runtime_token": record[2],
            "descriptor_va": desc_va,
            "base_record_va": base_record,
            "descriptor_word": desc_word,
            "record_refs": ptr_refs(record_va),
        }

    by_record = {r["record_va"]: name for name, r in records.items()}
    for r in records.values():
        r["base_name"] = by_record.get(r["base_record_va"])

    callback_tables = []
    seen = set()
    for name, r in records.items():
        for ref_va in r["record_refs"]:
            if ref_va == r["descriptor_va"]:
                continue
            off = va_to_off(ref_va)
            if off is None or off + 8 > len(data):
                continue
            # Scheduler callback tables use 8-byte slots: pointer, zero.
            if u32(data, off) != r["record_va"] or u32(data, off + 4) != 0:
                continue
            key = (name, ref_va)
            if key in seen:
                continue
            seen.add(key)
            slots = []
            cur = off
            for slot in range(32):
                if cur + 8 > len(data):
                    break
                ptr = u32(data, cur)
                pad = u32(data, cur + 4)
                va = off_to_va(cur)
                if slot == 0:
                    valid = ptr == r["record_va"] and pad == 0
                else:
                    valid = pad == 0 and (ptr == 0 or text_lo <= ptr < text_hi)
                if not valid:
                    break
                slots.append(
                    {
                        "slot": slot,
                        "entry_va": va,
                        "pointer": ptr,
                        "function": code_name(ptr),
                    }
                )
                cur += 8
            if len(slots) >= 2:
                callback_tables.append(
                    {
                        "class": name,
                        "table_va": ref_va,
                        "slots": slots,
                    }
                )

    result = {
        "image_base": image_base,
        "text_range": [text_lo, text_hi],
        "records": sorted(records.values(), key=lambda x: x["record_va"]),
        "callback_tables": sorted(callback_tables, key=lambda x: x["table_va"]),
    }
    output = json.dumps(result, indent=2) + "\n"
    if ns.output:
        ns.output.parent.mkdir(parents=True, exist_ok=True)
        ns.output.write_text(output, encoding="utf-8")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
