#!/usr/bin/env python3
"""Convert DumpVtableRefs.java output into store-only vptr initializer evidence.

Ghidra may attach the same DATA reference to both the immediate-load instruction
and the following memory store.  For constructor/destructor inference we keep
only instructions that visibly write through a memory operand.  This greatly
reduces false positives from code that merely compares or loads table addresses.
"""

from __future__ import annotations

import csv
from pathlib import Path


HERE = Path(__file__).resolve().parent
SOURCE = HERE / "vtable_xrefs.tsv"
DEST = HERE / "vptr_refs.tsv"


def main() -> int:
    with SOURCE.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))

    out_rows = []
    seen = set()
    for r in rows:
        ins = r.get("instruction", "")
        kind = r.get("target_kind") or r.get("literal_kind") or ""
        if kind != "table_header":
            continue
        if not ins.upper().startswith("MOV ") or "PTR [" not in ins.upper():
            continue
        function_entry = r.get("function_entry", "")
        if not function_entry:
            continue
        record_va = r.get("class_record_va") or r.get("record_va") or ""
        target_va = r.get("target_va") or r.get("table_header_va") or r.get("literal_va") or ""
        xref_from = r.get("xref_from") or r.get("instruction_va") or ""
        key = (record_va, target_va, xref_from, function_entry)
        if key in seen:
            continue
        seen.add(key)
        out_rows.append({
            "record_va": record_va.lower(),
            "class_name": r["class_name"],
            "vptr_va": target_va.lower(),
            "xref_from": xref_from.lower(),
            "ref_type": r.get("ref_type", "DATA"),
            "function_entry": function_entry.lower(),
            "function_name": r.get("function_name", ""),
        })

    with DEST.open("w", newline="", encoding="utf-8") as f:
        fields = ["record_va", "class_name", "vptr_va", "xref_from", "ref_type", "function_entry", "function_name"]
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(out_rows)

    print(f"wrote {len(out_rows)} store-backed vptr refs to {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
