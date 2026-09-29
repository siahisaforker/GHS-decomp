#!/usr/bin/env python3
"""Reproducible static anchors for the stripped GHS 5.3.22 ecomppc.exe.

This intentionally avoids pefile/capstone so it can run in the analysis tree with
only the Python standard library.  It extracts the PE map/imports, recovers the
small set of MSVC RTTI type descriptors/vtables, and records data references to
high-value compiler class/pass registry names.  When a Ghidra functions.tsv is
available, vtable code pointers are annotated with recovered function entries.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import hashlib
import json
import re
import struct
from pathlib import Path


REGISTRY_NAMES = (
    "SubstituteVariantsVisitor",
    "LivenessDf",
    "PostLivenessDf",
    "AliasAnalyzer",
    "TimeAccurateAliasAnalyzer",
    "BooleanAccurateAliasAnalyzer",
    "g4_resource_scheduler",
    "ppc970_resource_scheduler",
    "ame_resource_scheduler",
    "list_scheduler",
    "resource_model_scheduler",
    "compat_list_scheduler",
    "ls_window_scheduler",
    "spill_variable_set::listener",
)


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


def cstr(data: bytes, off: int, limit: int = 1024) -> str:
    end = data.find(b"\0", off, min(len(data), off + limit))
    if end < 0:
        end = min(len(data), off + limit)
    return data[off:end].decode("ascii", "replace")


def load_functions(path: Path | None) -> tuple[list[int], dict[int, str]]:
    if path is None or not path.exists():
        return [], {}
    names: dict[int, str] = {}
    with path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            names[int(row["entry"], 16)] = row["name"]
    return sorted(names), names


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("exe", type=Path)
    ap.add_argument("--functions", type=Path)
    ap.add_argument("-o", "--output", type=Path)
    ns = ap.parse_args()

    data = ns.exe.read_bytes()
    peoff = u32(data, 0x3C)
    if data[peoff:peoff + 4] != b"PE\0\0":
        raise SystemExit("not a PE file")
    coff = peoff + 4
    nsec = u16(data, coff + 2)
    timestamp = u32(data, coff + 4)
    opt_size = u16(data, coff + 16)
    opt = coff + 20
    if u16(data, opt) != 0x10B:
        raise SystemExit("expected PE32")
    entry_rva = u32(data, opt + 16)
    image_base = u32(data, opt + 28)
    size_image = u32(data, opt + 56)
    section_table = opt + opt_size

    sections = []
    for i in range(nsec):
        off = section_table + i * 40
        name = data[off:off + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size = u32(data, off + 8)
        virtual_address = u32(data, off + 12)
        raw_size = u32(data, off + 16)
        raw_offset = u32(data, off + 20)
        characteristics = u32(data, off + 36)
        sections.append({
            "name": name,
            "rva": virtual_address,
            "va": image_base + virtual_address,
            "virtual_size": virtual_size,
            "raw_offset": raw_offset,
            "raw_size": raw_size,
            "characteristics": characteristics,
        })

    def rva_to_off(rva: int) -> int | None:
        for s in sections:
            span = max(s["virtual_size"], s["raw_size"])
            if s["rva"] <= rva < s["rva"] + span:
                delta = rva - s["rva"]
                if delta < s["raw_size"]:
                    return s["raw_offset"] + delta
        return None

    def va_to_off(va: int) -> int | None:
        return rva_to_off(va - image_base)

    import_rva = u32(data, opt + 96 + 8)
    import_off = rva_to_off(import_rva) if import_rva else None
    imports = []
    if import_off is not None:
        pos = import_off
        while True:
            oft, stamp, chain, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
            if not any((oft, stamp, chain, name_rva, ft)):
                break
            name_off = rva_to_off(name_rva)
            dll = cstr(data, name_off) if name_off is not None else f"rva_{name_rva:08x}"
            thunk_rva = oft or ft
            thunk_off = rva_to_off(thunk_rva)
            symbols = []
            if thunk_off is not None:
                t = thunk_off
                while True:
                    val = u32(data, t)
                    if val == 0:
                        break
                    if val & 0x80000000:
                        symbols.append({"ordinal": val & 0xFFFF})
                    else:
                        hn = rva_to_off(val)
                        if hn is not None:
                            symbols.append({"hint": u16(data, hn), "name": cstr(data, hn + 2)})
                    t += 4
            imports.append({"dll": dll, "iat_va": image_base + ft, "symbols": symbols})
            pos += 20

    starts, function_names = load_functions(ns.functions)
    text = next((s for s in sections if s["name"] == ".text"), None)
    text_lo = text["va"] if text else 0
    text_hi = text_lo + (max(text["virtual_size"], text["raw_size"]) if text else 0)

    def describe_code(va: int) -> str | None:
        if not (text_lo <= va < text_hi):
            return None
        if va in function_names:
            return function_names[va]
        if not starts:
            return None
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and va - starts[i] < 0x10000:
            return f"{function_names[starts[i]]}+0x{va - starts[i]:x}"
        return None

    rtti = []
    for m in re.finditer(rb"\.\?A[UV][ -~]{1,96}\x00", data):
        td_off = m.start() - 8
        if td_off < 0:
            continue
        td_va = image_base + next(
            (s["rva"] + td_off - s["raw_offset"] for s in sections
             if s["raw_offset"] <= td_off < s["raw_offset"] + s["raw_size"]),
            -image_base,
        )
        if td_va <= 0:
            continue
        name = m.group()[:-1].decode("ascii", "replace")
        td_ptr = struct.pack("<I", td_va)
        cols = []
        pos = 0
        while True:
            ref_off = data.find(td_ptr, pos)
            if ref_off < 0:
                break
            col_off = ref_off - 12
            if col_off >= 0:
                col_va = image_base + next(
                    (s["rva"] + col_off - s["raw_offset"] for s in sections
                     if s["raw_offset"] <= col_off < s["raw_offset"] + s["raw_size"]),
                    -image_base,
                )
                if col_va > 0 and u32(data, col_off) == 0:
                    col_ptr = struct.pack("<I", col_va)
                    q = 0
                    while True:
                        meta_off = data.find(col_ptr, q)
                        if meta_off < 0:
                            break
                        meta_va = image_base + next(
                            (s["rva"] + meta_off - s["raw_offset"] for s in sections
                             if s["raw_offset"] <= meta_off < s["raw_offset"] + s["raw_size"]),
                            -image_base,
                        )
                        if meta_va > 0:
                            vt_va = meta_va + 4
                            vt_off = va_to_off(vt_va)
                            entries = []
                            if vt_off is not None:
                                for i in range(8):
                                    fva = u32(data, vt_off + i * 4)
                                    if not (text_lo <= fva < text_hi):
                                        break
                                    entries.append({"va": fva, "function": describe_code(fva)})
                            cols.append({"complete_object_locator_va": col_va, "vftable_va": vt_va, "entries": entries})
                        q = meta_off + 1
            pos = ref_off + 1
        if cols:
            # The raw pointer scan can find the same COL/vftable pair through more than one route.
            uniq = {(x["complete_object_locator_va"], x["vftable_va"]): x for x in cols}
            rtti.append({"type_descriptor_va": td_va, "name": name, "objects": list(uniq.values())})

    registries = []
    for name in REGISTRY_NAMES:
        needle = name.encode() + b"\0"
        matches = []
        pos = 0
        while True:
            so = data.find(needle, pos)
            if so < 0:
                break
            prev = data[so - 1] if so else 0
            if not (chr(prev).isalnum() or prev in b"_:"):
                matches.append(so)
            pos = so + 1
        if not matches:
            continue
        # Prefer an occurrence that is actually referenced as a pointer.  This
        # disambiguates names such as "list_scheduler" from the suffix of
        # "compat_list_scheduler".
        so = matches[0]
        for candidate in matches:
            candidate_va = image_base + next(
                (s["rva"] + candidate - s["raw_offset"] for s in sections
                 if s["raw_offset"] <= candidate < s["raw_offset"] + s["raw_size"]),
                -image_base,
            )
            if candidate_va > 0 and data.find(struct.pack("<I", candidate_va)) >= 0:
                so = candidate
                break
        sva = image_base + next(
            (s["rva"] + so - s["raw_offset"] for s in sections
             if s["raw_offset"] <= so < s["raw_offset"] + s["raw_size"]),
            -image_base,
        )
        refs = []
        if sva > 0:
            packed = struct.pack("<I", sva)
            p = 0
            while True:
                ro = data.find(packed, p)
                if ro < 0:
                    break
                rva = image_base + next(
                    (s["rva"] + ro - s["raw_offset"] for s in sections
                     if s["raw_offset"] <= ro < s["raw_offset"] + s["raw_size"]),
                    -image_base,
                )
                if rva > 0:
                    refs.append(rva)
                p = ro + 1
        registries.append({"name": name, "string_va": sva, "pointer_refs": refs})

    result = {
        "file": str(ns.exe),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "timestamp": timestamp,
        "image_base": image_base,
        "entry_rva": entry_rva,
        "entry_va": image_base + entry_rva,
        "size_of_image": size_image,
        "sections": sections,
        "imports": imports,
        "msvc_rtti": rtti,
        "named_registries": registries,
    }
    text = json.dumps(result, indent=2)
    if ns.output:
        ns.output.parent.mkdir(parents=True, exist_ok=True)
        ns.output.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
