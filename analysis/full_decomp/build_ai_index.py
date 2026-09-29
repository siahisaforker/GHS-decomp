#!/usr/bin/env python3
"""Build a compact AI-consumption index for newly exported decompiler C."""

from __future__ import annotations

import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
ADDR_RE = re.compile(r"([0-9A-Fa-f]{8})_")
SLOT_RE = re.compile(r"(?P<adjust>[+-]?\d+):0x(?P<va>[0-9A-Fa-f]{8})")


def rows(path: Path):
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        yield from csv.DictReader(f, delimiter="\t")


def clean(s: str) -> str:
    return s.replace("\t", " ").replace("\r", " ").replace("\n", "\\n")


def boolish(v: str) -> bool:
    return v.lower() == "true"


def context_score(r: dict[str, str]) -> float:
    score = 0.0
    score += 8.0 if boolish(r.get("curated_name", "")) else 0.0
    score += 4.0 if r.get("direct_source") else 0.0
    score += 3.0 if boolish(r.get("semantic_name", "")) else 0.0
    score += 2.0 if boolish(r.get("vtable_member", "")) else 0.0
    score += math.log2(1 + int(r.get("caller_refs", "0") or 0) + int(r.get("callee_count", "0") or 0))
    return score


def main() -> int:
    coverage = {r["entry"].lower(): r for r in rows(HERE / "coverage.tsv")}

    membership = {}
    membership_path = HERE / "checkpoint_pre_wave/batch_membership.tsv"
    if membership_path.is_file():
        for r in rows(membership_path):
            membership[r["entry"].lower()] = r
    for receipt in sorted(HERE.glob("exports*/export_receipt.json")):
        data = json.loads(receipt.read_text(encoding="utf-8"))
        for m in data.get("membership", []):
            membership[m["va"].removeprefix("0x").lower()] = {
                "batch_id": m["batch_id"],
                "wave": m["wave"],
                "module": m["module"],
            }

    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    for r in rows(HERE / "callgraph.tsv"):
        a, b = r["caller_addr"].lower(), r["callee_addr"].lower()
        if a in coverage and b in coverage:
            callees[a].add(b)
            callers[b].add(a)

    string_refs: dict[str, Counter] = defaultdict(Counter)
    string_addrs: dict[tuple[str, str], str] = {}
    for r in rows(ROOT / "analysis/ghidra/out/all_string_xrefs.tsv"):
        a = r["function_entry"].lower()
        if a not in coverage:
            continue
        text = clean(r["string"])
        key = (r["string_addr"].lower(), text)
        string_refs[a][key] += 1
        string_addrs[key] = r["string_addr"].lower()

    registry_by_name: dict[str, list[dict]] = defaultdict(list)
    for r in rows(ROOT / "analysis/worker3_static_map/ghs_registry.tsv"):
        registry_by_name[r["name"]].append({
            "record_va": r["record_va"],
            "category": r["category"],
            "primary_base_record_va": r["primary_base_record_va"],
            "primary_base_name": r["primary_base_name"],
        })

    vtable_slots: dict[str, list[dict]] = defaultdict(list)
    for r in rows(ROOT / "analysis/worker3_static_map/ghs_vtables.tsv"):
        for slot_index, token in enumerate(r["slots"].split(",")):
            m = SLOT_RE.fullmatch(token.strip())
            if not m:
                continue
            a = m.group("va").lower()
            vtable_slots[a].append({
                "class_name": r["name"],
                "record_va": r["record_va"].lower(),
                "vptr_va": r["vptr_va"].lower(),
                "slot_index": slot_index,
                "this_adjust": int(m.group("adjust")),
                "target_va": "0x" + a,
            })

    exported = []
    export_paths = set((HERE / "exports_wave").glob("*/*.c"))
    export_paths.update(HERE.glob("exports/*/*.c"))
    export_paths.update(HERE.glob("exports_*/*/*.c"))
    for p in sorted(export_paths):
        m = ADDR_RE.match(p.name)
        if not m:
            continue
        a = m.group(1).lower()
        if a not in coverage:
            continue
        exported.append((a, p))

    def neighbor(a: str) -> dict:
        r = coverage[a]
        return {
            "entry": a,
            "name": r["name"],
            "module": r["module"],
            "wave": r["wave"],
            "semantic_name": boolish(r["semantic_name"]),
            "direct_source": r["direct_source"],
            "vtable_classes": [x for x in r["vtable_classes"].split(";") if x],
            "context_score": round(context_score(r), 3),
        }

    output = []
    hypothesis_rows = []
    for a, path in exported:
        r = coverage[a]
        bm = membership.get(a, {})
        class_names = [x for x in r["vtable_classes"].split(";") if x]
        registry = []
        seen_registry = set()
        for cls in class_names:
            for rec in registry_by_name.get(cls, []):
                key = (cls, rec["record_va"])
                if key in seen_registry:
                    continue
                seen_registry.add(key)
                registry.append({"class": cls, **rec})

        top_callers = sorted(callers.get(a, ()), key=lambda x: (-context_score(coverage[x]), x))[:8]
        top_callees = sorted(callees.get(a, ()), key=lambda x: (-context_score(coverage[x]), x))[:8]
        strings = [
            {"string_addr": key[0], "text": key[1], "xref_count": count}
            for key, count in sorted(
                string_refs.get(a, {}).items(),
                key=lambda kv: (-kv[1], -len(kv[0][1]), kv[0][0]),
            )[:12]
        ]
        options = [s for s in strings if s["text"].startswith("-")]
        raw_name = ("FUN_" + a.upper()) if r["name_source"] == "USER_DEFINED" else r["name"]
        proposed_name = r["name"] if r["name_source"] == "USER_DEFINED" else ""

        hypotheses = []
        if r["direct_source"]:
            h = {
                "va": "0x" + a,
                "raw_name": raw_name,
                "proposed_name": proposed_name,
                "hypothesis_kind": "source_file_association",
                "value": r["direct_source"],
                "confidence": float(r["source_confidence"] or 0),
                "evidence_kinds": ["embedded_source_string_xref"],
                "evidence_refs": [f"analysis/prime/source_file_function_map.tsv#function_entry={a}"],
                "provenance": "analysis/full_decomp/build_coverage.py",
                "source_file": "analysis/prime/source_file_function_map.tsv",
            }
            hypotheses.append(h)
            hypothesis_rows.append(h)
        if r["module"]:
            kinds = {
                "direct_source": ["embedded_source_string_xref"],
                "address": ["address_bracketed_source_anchors"],
                "graph": ["callgraph_source_neighbor_consensus"],
                "graph+address": ["address_bracketed_source_anchors", "callgraph_source_neighbor_consensus"],
                "vtable": ["vtable_class_membership"],
            }.get(r["module_evidence"], [r["module_evidence"] or "unknown"])
            refs = []
            if "source" in " ".join(kinds):
                refs.append(f"analysis/prime/source_file_function_map.tsv#function_entry={a}")
            if any("callgraph" in x for x in kinds):
                refs.append(f"analysis/full_decomp/callgraph.tsv#va={a}")
            if any("address" in x for x in kinds):
                refs.append("analysis/ghidra/out/inventory/functions.tsv")
            if any("vtable" in x for x in kinds):
                refs.append(f"analysis/worker3_static_map/ghs_vtables.tsv#target_va=0x{a}")
            h = {
                "va": "0x" + a,
                "raw_name": raw_name,
                "proposed_name": proposed_name,
                "hypothesis_kind": "module_assignment",
                "value": r["module"],
                "confidence": float(r["module_confidence"] or 0),
                "evidence_kinds": kinds,
                "evidence_refs": refs,
                "provenance": "analysis/full_decomp/build_coverage.py",
                "source_file": "analysis/full_decomp/coverage.tsv",
            }
            hypotheses.append(h)
            hypothesis_rows.append(h)

        output.append({
            "schema_version": 2,
            "record_kind": "decompiled_function_index",
            "va": "0x" + a,
            "raw_name": raw_name,
            "proposed_name": proposed_name,
            "current_ghidra_name": r["name"],
            "name_source": r["name_source"],
            "body_size": int(r["body_size"]),
            "export_path": str(path.relative_to(ROOT)),
            "batch_id_pre_wave": bm.get("batch_id", ""),
            "wave": bm.get("wave", r["wave"]),
            "module": r["module"],
            "module_evidence": r["module_evidence"],
            "module_confidence": float(r["module_confidence"] or 0),
            "direct_source": r["direct_source"],
            "source_confidence": float(r["source_confidence"] or 0),
            "observed": {
                "decompiled_export": True,
                "semantic_name_present": boolish(r["semantic_name"]),
                "curated_user_name_present": boolish(r["curated_name"]),
                "vtable_slots": sorted(vtable_slots.get(a, []), key=lambda x: (x["record_va"], x["slot_index"])),
                "registry_records": registry,
                "string_ref_count": sum(string_refs.get(a, {}).values()),
                "strings": strings,
                "options": options,
                "caller_count": len(callers.get(a, ())),
                "callee_count": len(callees.get(a, ())),
                "strongest_callers": [neighbor(x) for x in top_callers],
                "strongest_callees": [neighbor(x) for x in top_callees],
                "evidence_refs": [
                    str(path.relative_to(ROOT)),
                    f"analysis/full_decomp/callgraph.tsv#va={a}",
                    f"analysis/ghidra/out/all_string_xrefs.tsv#function_entry={a}",
                    f"analysis/worker3_static_map/ghs_vtables.tsv#target_va=0x{a}",
                ],
            },
            "hypotheses": hypotheses,
            "confidence": 1.0,
            "evidence_kinds": ["ghidra_decompiler_export"],
            "evidence_refs": [str(path.relative_to(ROOT))],
            "provenance": "analysis/full_decomp/build_ai_index.py",
            "source_file": str(path.relative_to(ROOT)),
            "vtable_classes": class_names,
            "vtable_categories": [x for x in r["vtable_categories"].split(";") if x],
        })

    with (HERE / "export_index.jsonl").open("w", encoding="utf-8") as f:
        for r in output:
            f.write(json.dumps(r, sort_keys=True) + "\n")

    with (HERE / "export_hypotheses.jsonl").open("w", encoding="utf-8") as f:
        for r in sorted(hypothesis_rows, key=lambda x: (x["va"], x["hypothesis_kind"], x["value"])):
            f.write(json.dumps(r, sort_keys=True) + "\n")

    fields = [
        "va", "raw_name", "proposed_name", "body_size", "export_path", "batch_id_pre_wave", "wave", "module",
        "module_evidence", "module_confidence", "direct_source", "source_confidence",
        "vtable_classes", "vtable_slots", "registry_evidence", "string_ref_count", "strings", "options",
        "strongest_callers", "strongest_callees",
    ]
    with (HERE / "export_index.tsv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
        w.writeheader()
        for r in output:
            w.writerow({
                "va": r["va"],
                "raw_name": r["raw_name"],
                "proposed_name": r["proposed_name"],
                "body_size": r["body_size"],
                "export_path": r["export_path"],
                "batch_id_pre_wave": r["batch_id_pre_wave"],
                "wave": r["wave"],
                "module": r["module"],
                "module_evidence": r["module_evidence"],
                "module_confidence": r["module_confidence"],
                "direct_source": r["direct_source"],
                "source_confidence": r["source_confidence"],
                "vtable_classes": ";".join(r["vtable_classes"]),
                "vtable_slots": json.dumps(r["observed"]["vtable_slots"], separators=(",", ":")),
                "registry_evidence": json.dumps(r["observed"]["registry_records"], separators=(",", ":")),
                "string_ref_count": r["observed"]["string_ref_count"],
                "strings": json.dumps(r["observed"]["strings"], separators=(",", ":")),
                "options": json.dumps(r["observed"]["options"], separators=(",", ":")),
                "strongest_callers": json.dumps(r["observed"]["strongest_callers"], separators=(",", ":")),
                "strongest_callees": json.dumps(r["observed"]["strongest_callees"], separators=(",", ":")),
            })

    summary = Counter(r["wave"] for r in output)
    meta = {
        "exported_functions": len(output),
        "by_wave": dict(sorted(summary.items())),
        "hypothesis_rows": len(hypothesis_rows),
        "with_strings": sum(bool(r["observed"]["strings"]) for r in output),
        "with_vtable_classes": sum(bool(r["vtable_classes"]) for r in output),
        "with_vtable_slots": sum(bool(r["observed"]["vtable_slots"]) for r in output),
        "with_registry_evidence": sum(bool(r["observed"]["registry_records"]) for r in output),
        "with_callers": sum(bool(r["observed"]["strongest_callers"]) for r in output),
        "with_callees": sum(bool(r["observed"]["strongest_callees"]) for r in output),
        "provenance": "analysis/full_decomp/build_ai_index.py",
    }
    (HERE / "export_index_summary.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
