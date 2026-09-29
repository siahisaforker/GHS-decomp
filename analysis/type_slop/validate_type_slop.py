#!/usr/bin/env python3
"""Sanity-check the generated type-slop maps and a few durable anchors."""

from __future__ import annotations

import csv
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def tsv(name: str) -> list[dict[str, str]]:
    with (HERE / name).open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def require(value: bool, message: str) -> None:
    if not value:
        raise SystemExit(f"FAIL: {message}")


def main() -> int:
    groups = tsv("class_groups.tsv")
    hierarchy = tsv("hierarchy.tsv")
    slots = tsv("virtual_slots.tsv")
    hyps = tsv("function_hypotheses.tsv")
    backend = tsv("backend_hierarchy.tsv")
    backend_slots = tsv("backend_slots.tsv")
    vptr_refs = tsv("vptr_refs.tsv")
    type_map = json.loads((HERE / "type_map.json").read_text(encoding="utf-8"))

    require(len(hierarchy) == 428, f"expected 428 registry rows, got {len(hierarchy)}")
    require(len(slots) == 2605, f"expected 2605 virtual slot rows, got {len(slots)}")
    require(len(vptr_refs) == 420, f"expected 420 store-backed vptr refs, got {len(vptr_refs)}")
    require(len(backend_slots) == 814, f"expected 814 backend hierarchy slots, got {len(backend_slots)}")
    require(len(groups) >= 70, f"class grouping unexpectedly collapsed to {len(groups)} groups")

    chain = [r["class_name"] for r in sorted(backend, key=lambda r: int(r["depth"]))]
    require(
        chain == ["backend_dataflow", "backend_basetype", "backend_basetype2", "backend_t"],
        f"unexpected backend chain: {chain}",
    )
    require([int(r["slot_count"]) for r in sorted(backend, key=lambda r: int(r["depth"]))] == [28, 262, 262, 262],
            "backend slot counts changed")

    by_addr = {r["function_entry"]: r for r in hyps}
    anchors = {
        "00424ceb": ("backend_t", {"constructor"}),
        "00486b99": ("g4_resource_scheduler", {"constructor_like", "constructor_or_destructor_like"}),
        "00487f60": ("ppc970_resource_scheduler", {"constructor_like", "constructor_or_destructor_like"}),
        "0048a79c": ("ame_resource_scheduler", {"constructor_like", "constructor_or_destructor_like"}),
        # Store order is base table -> derived table, so these are now stronger
        # constructor-like hypotheses than the earlier lifecycle-only label.
        "0071df17": ("alloc_table_hash", {"constructor_like", "constructor_or_destructor_like"}),
        "0071df90": ("alloc_table_btree", {"constructor_like", "constructor_or_destructor_like"}),
        "0071e0e0": ("alloc_table_bcl", {"constructor_like", "constructor_or_destructor_like"}),
    }
    for addr, (needle, roles) in anchors.items():
        require(addr in by_addr, f"missing anchor {addr}")
        row = by_addr[addr]
        require(row["role"] in roles, f"{addr} role changed: {row['role']}")
        combined = row["classes"] + ";" + row["proposed_name"]
        require(needle in combined, f"{addr} lost {needle} association")

    summary = type_map["summary"]
    require(summary["registry_records"] == 428, "type_map summary registry count mismatch")
    require(summary["vtables"] == 253, "type_map summary vtable count mismatch")
    require(summary["virtual_slot_entries"] == 2605, "type_map summary slot count mismatch")
    require(summary["vptr_xref_rows"] == 420, "type_map summary vptr-ref count mismatch")

    print(
        "OK: "
        f"{len(hierarchy)} classes, {len(groups)} groups, {len(slots)} virtual slots, "
        f"{len(vptr_refs)} store-backed vptr refs, {len(hyps)} function hypotheses"
    )
    print("OK: backend_dataflow -> backend_basetype -> backend_basetype2 -> backend_t")
    print("OK: backend, scheduler, and alloc_table constructor anchors present")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
