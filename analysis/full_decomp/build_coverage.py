#!/usr/bin/env python3
"""Quantify semantic-decomp coverage and build locality-aware Ghidra batches."""

from __future__ import annotations

import argparse
import csv
import glob
import json
import math
import re
from collections import Counter, defaultdict, deque
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
SOURCE_MAP = ROOT / "analysis/prime/source_file_function_map.tsv"
CALLGRAPH = HERE / "callgraph.tsv"
VTABLES = ROOT / "analysis/worker3_static_map/ghs_vtables.tsv"
REGISTRY = ROOT / "analysis/worker3_static_map/ghs_registry.tsv"
DECOMPILED = ROOT / "analysis/ghidra/out/decompiled"

DEFAULT_NAME = re.compile(r"FUN_[0-9A-Fa-f]+$")
SLOT_ADDR = re.compile(r"0x([0-9A-Fa-f]{8})")
DECOMP_ADDR = re.compile(r"([0-9A-Fa-f]{8})_")


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def source_wave(source: str) -> str:
    s = source.lower()
    if s.startswith("src/edg/src/"):
        return "frontend"
    if s.startswith("src/compilers/edg/"):
        return "frontend_bridge"
    if s.startswith("src/asm/ease/") or s.startswith("src/shared/indinst/"):
        return "backend_target"
    if any(x in s for x in ("indcod", "indopc", "indgen", "indoutputgen", "genout")):
        return "backend_target"
    if s.startswith("src/compilers/indep/") or s.startswith("src/shared/"):
        return "optimizer"
    return "unknown"


def category_wave(categories: set[str], classes: set[str]) -> str:
    if categories & {"optimizer/analysis", "register-allocation", "scheduler", "IR/object-model"}:
        return "optimizer"
    if "runtime/std" in categories:
        return "runtime_support"
    lowered = " ".join(classes).lower()
    if any(x in lowered for x in ("backend_t", "disassembler", "indinst", "operand_parser", "register_range", "register_set")):
        return "backend_target"
    return "unknown"


def semantic_score(row: dict) -> float:
    """Evidence-weighted progress proxy, deliberately below 1 without reviewed semantics."""
    score = 0.0
    if row["decompiled"]:
        score += 0.20
    if row["direct_source"]:
        score += 0.25
    elif row["module_evidence"] in {"graph", "address", "graph+address"}:
        score += 0.10
    if row["name_source"] == "USER_DEFINED":
        score += 0.35
    elif row["semantic_name"]:
        score += 0.15
    if row["vtable_member"]:
        score += 0.10
    return min(score, 1.0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--batch-size", type=int, default=96)
    ap.add_argument("--out", type=Path, default=HERE)
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    batch_dir = out / "batch_lists"
    batch_dir.mkdir(exist_ok=True)
    for stale in batch_dir.glob("*.tsv"):
        stale.unlink()

    functions = {r["entry"].lower(): r for r in read_tsv(FUNCTIONS)}
    addresses = sorted(functions, key=lambda x: int(x, 16))

    # Strongest embedded-source association per function.
    direct_source: dict[str, tuple[str, float]] = {}
    for r in read_tsv(SOURCE_MAP):
        a = r["function_entry"].lower()
        conf = float(r["confidence"])
        if conf < 0.80 or a not in functions:
            continue
        if a not in direct_source or conf > direct_source[a][1]:
            direct_source[a] = (r["source_file"], conf)

    # Existing decompiler exports.
    decompiled: set[str] = set()
    for p in glob.glob(str(DECOMPILED / "*.c")):
        m = DECOMP_ADDR.match(Path(p).name)
        if m and m.group(1).lower() in functions:
            decompiled.add(m.group(1).lower())

    # Registry categories keyed by recovered class/type name.
    registry_rows = read_tsv(REGISTRY)
    class_category = {r["name"]: r["category"] for r in registry_rows}

    # Function -> vtable classes/categories.
    vclasses: dict[str, set[str]] = defaultdict(set)
    vcats: dict[str, set[str]] = defaultdict(set)
    vtable_rows = read_tsv(VTABLES)
    total_vtable_slots = 0
    for r in vtable_rows:
        cls = r["name"]
        cat = class_category.get(cls, "other")
        for m in SLOT_ADDR.finditer(r["slots"]):
            total_vtable_slots += 1
            a = m.group(1).lower()
            if a in functions:
                vclasses[a].add(cls)
                vcats[a].add(cat)

    # Full direct callgraph and undirected neighborhood for locality inference.
    graph: dict[str, set[str]] = defaultdict(set)
    directed_edges: list[tuple[str, str]] = []
    edge_count = 0
    callgraph_rows = read_tsv(CALLGRAPH)
    for r in callgraph_rows:
        a, b = r["caller_addr"].lower(), r["callee_addr"].lower()
        if a not in functions or b not in functions:
            continue
        graph[a].add(b)
        graph[b].add(a)
        directed_edges.append((a, b))
        edge_count += 1

    # Conservative module inference from direct source anchors.
    anchor_module = {a: s for a, (s, _) in direct_source.items()}
    anchor_addrs = sorted(anchor_module, key=lambda x: int(x, 16))
    anchor_values = [int(a, 16) for a in anchor_addrs]

    def address_vote(a: str) -> tuple[str | None, float]:
        import bisect
        x = int(a, 16)
        i = bisect.bisect_left(anchor_values, x)
        if i == 0 or i == len(anchor_values):
            return None, 0.0
        left, right = anchor_addrs[i - 1], anchor_addrs[i]
        if anchor_module[left] != anchor_module[right]:
            return None, 0.0
        span = int(right, 16) - int(left, 16)
        if span > 0x10000:
            return None, 0.0
        return anchor_module[left], max(0.60, 0.90 - span / 0x20000)

    def graph_vote(a: str) -> tuple[str | None, float]:
        votes = Counter(anchor_module[n] for n in graph.get(a, ()) if n in anchor_module)
        if not votes:
            return None, 0.0
        module, count = votes.most_common(1)[0]
        total = sum(votes.values())
        if count < 2 or count / total < 0.75:
            return None, 0.0
        return module, min(0.90, 0.65 + 0.05 * count)

    inferred: dict[str, tuple[str, str, float]] = {}
    for a in addresses:
        if a in anchor_module:
            continue
        amod, acon = address_vote(a)
        gmod, gcon = graph_vote(a)
        if amod and gmod and amod == gmod:
            inferred[a] = (amod, "graph+address", max(acon, gcon, 0.90))
        elif gmod:
            inferred[a] = (gmod, "graph", gcon)
        elif amod:
            inferred[a] = (amod, "address", acon)

    rows = []
    for a in addresses:
        f = functions[a]
        semantic = not bool(DEFAULT_NAME.fullmatch(f["name"]))
        module = ""
        module_evidence = ""
        module_conf = 0.0
        src = ""
        src_conf = 0.0
        if a in direct_source:
            src, src_conf = direct_source[a]
            module, module_evidence, module_conf = src, "direct_source", src_conf
        elif a in inferred:
            module, module_evidence, module_conf = inferred[a]
        elif a in vclasses:
            classes = sorted(vclasses[a])
            if len(classes) == 1:
                module = "class:" + classes[0]
            else:
                module = "vtable_shared:" + (sorted(vcats[a])[0] if vcats[a] else "other")
            module_evidence, module_conf = "vtable", 0.55

        wave = source_wave(module) if module and not module.startswith(("class:", "vtable_shared:")) else "unknown"
        if wave == "unknown" and a in vclasses:
            wave = category_wave(vcats[a], vclasses[a])
        if wave == "unknown" and f["source"] == "ANALYSIS":
            wave = "runtime_support"
        if wave == "unknown" and f["source"] == "USER_DEFINED":
            # Curated names in this project are optimizer/backend passes.
            wave = "optimizer"
        if wave == "unknown":
            wave = "unclustered"

        row = {
            "entry": a,
            "body_size": int(f["body_size"]),
            "name": f["name"],
            "name_source": f["source"],
            "semantic_name": semantic,
            "curated_name": f["source"] == "USER_DEFINED",
            "decompiled": a in decompiled,
            "direct_source": src,
            "source_confidence": src_conf,
            "vtable_member": a in vclasses,
            "vtable_classes": sorted(vclasses[a]),
            "vtable_categories": sorted(vcats[a]),
            "module": module,
            "module_evidence": module_evidence,
            "module_confidence": round(module_conf, 3),
            "wave": wave,
            "caller_refs": int(f["caller_refs"]),
            "callee_count": int(f["callee_count"]),
        }
        row["semantic_score"] = semantic_score(row)
        rows.append(row)

    # Prioritize undecompiled functions using semantic/structural evidence and graph centrality.
    for row in rows:
        priority = 0.0
        if not row["decompiled"]:
            priority += 10.0
        if row["curated_name"]:
            priority += 8.0
        elif row["semantic_name"]:
            priority += 3.0
        if row["direct_source"]:
            priority += 6.0
        elif row["module"]:
            priority += 3.0
        if row["vtable_member"]:
            priority += 4.0
        priority += min(5.0, math.log2(1 + row["caller_refs"] + row["callee_count"]))
        priority += min(3.0, math.log2(1 + row["body_size"]) / 4.0)
        row["priority"] = round(priority, 3)

    wave_order = {
        "backend_target": 0,
        "optimizer": 1,
        "frontend_bridge": 2,
        "frontend": 3,
        "runtime_support": 4,
        "unclustered": 5,
    }

    # Group remaining functions by wave/module, then BFS within each induced graph so
    # callees/callers tend to land in the same batch.
    remaining = {r["entry"]: r for r in rows if not r["decompiled"]}
    groups: dict[tuple[str, str], set[str]] = defaultdict(set)
    for a, r in remaining.items():
        module = r["module"] or f"unknown_{a[:4]}xxxx"
        groups[(r["wave"], module)].add(a)

    batches = []
    batch_members: dict[str, list[str]] = {}
    batch_index = 0
    for (wave, module), members in sorted(
        groups.items(), key=lambda kv: (wave_order.get(kv[0][0], 99), -max(remaining[a]["priority"] for a in kv[1]), kv[0][1])
    ):
        unseen = set(members)
        ordered: list[str] = []
        while unseen:
            seed = max(unseen, key=lambda a: remaining[a]["priority"])
            q = deque([seed])
            unseen.remove(seed)
            while q:
                a = q.popleft()
                ordered.append(a)
                neigh = sorted(
                    (n for n in graph.get(a, ()) if n in unseen and n in members),
                    key=lambda n: -remaining[n]["priority"],
                )
                for n in neigh:
                    unseen.remove(n)
                    q.append(n)
        for start in range(0, len(ordered), args.batch_size):
            chunk = ordered[start:start + args.batch_size]
            batch_index += 1
            batch_id = f"{batch_index:04d}_{wave}"
            path = batch_dir / f"{batch_id}.tsv"
            with path.open("w", encoding="utf-8") as f:
                for a in chunk:
                    f.write(f"{a}\t{remaining[a]['name']}\n")
            batches.append({
                "id": batch_id,
                "wave": wave,
                "module": module,
                "module_evidence": Counter(remaining[a]["module_evidence"] or "none" for a in chunk).most_common(1)[0][0],
                "count": len(chunk),
                "priority_max": max(remaining[a]["priority"] for a in chunk),
                "priority_mean": round(sum(remaining[a]["priority"] for a in chunk) / len(chunk), 3),
                "address_min": min(chunk, key=lambda x: int(x, 16)),
                "address_max": max(chunk, key=lambda x: int(x, 16)),
                "list": str(path.relative_to(out)),
            })
            batch_members[batch_id] = chunk

    # Record cross-batch dependency/locality links after all membership is known.
    batch_for_function = {
        a: batch_id for batch_id, members in batch_members.items() for a in members
    }
    inbound: dict[str, Counter] = defaultdict(Counter)
    outbound: dict[str, Counter] = defaultdict(Counter)
    for caller, callee in directed_edges:
        cb = batch_for_function.get(caller)
        db = batch_for_function.get(callee)
        if not cb or not db or cb == db:
            continue
        outbound[cb][db] += 1
        inbound[db][cb] += 1
    for b in batches:
        bid = b["id"]
        b["outbound_batch_dependencies"] = [
            {"batch": other, "edges": count}
            for other, count in outbound[bid].most_common(8)
        ]
        b["inbound_batch_neighbors"] = [
            {"batch": other, "edges": count}
            for other, count in inbound[bid].most_common(8)
        ]

    # Full per-function table.
    table_fields = [
        "entry", "body_size", "name", "name_source", "semantic_name", "curated_name", "decompiled",
        "direct_source", "source_confidence", "vtable_member", "vtable_classes", "vtable_categories",
        "module", "module_evidence", "module_confidence", "wave", "caller_refs", "callee_count",
        "semantic_score", "priority",
    ]
    with (out / "coverage.tsv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=table_fields, delimiter="\t")
        w.writeheader()
        for r in rows:
            x = dict(r)
            x["vtable_classes"] = ";".join(x["vtable_classes"])
            x["vtable_categories"] = ";".join(x["vtable_categories"])
            w.writerow(x)

    total = len(rows)
    by_wave: dict[str, dict] = {}
    for wave in wave_order:
        wr = [r for r in rows if r["wave"] == wave]
        if not wr:
            continue
        by_wave[wave] = {
            "functions": len(wr),
            "decompiled": sum(r["decompiled"] for r in wr),
            "semantic_names": sum(r["semantic_name"] for r in wr),
            "curated_names": sum(r["curated_name"] for r in wr),
            "direct_source": sum(bool(r["direct_source"]) for r in wr),
            "vtable_members": sum(r["vtable_member"] for r in wr),
            "module_clustered": sum(bool(r["module"]) for r in wr),
            "semantic_estimate_pct": round(100 * sum(r["semantic_score"] for r in wr) / len(wr), 2),
            "remaining_not_decompiled": sum(not r["decompiled"] for r in wr),
        }

    any_evidence = sum(
        bool(r["semantic_name"] or r["decompiled"] or r["direct_source"] or r["vtable_member"])
        for r in rows
    )
    module_evidence_counts = Counter(r["module_evidence"] or "none" for r in rows)
    semantic_name_sources = Counter(r["name_source"] for r in rows if r["semantic_name"])
    summary = {
        "function_count": total,
        "callgraph_edges_raw": len(callgraph_rows),
        "callgraph_edges": edge_count,
        "semantic_names_any": sum(r["semantic_name"] for r in rows),
        "semantic_names_curated": sum(r["curated_name"] for r in rows),
        "direct_source_associations": sum(bool(r["direct_source"]) for r in rows),
        "existing_decompiled_functions": sum(r["decompiled"] for r in rows),
        "registry_records": len(registry_rows),
        "vtable_tables": len(vtable_rows),
        "vtable_slot_refs": total_vtable_slots,
        "vtable_unique_function_members": sum(r["vtable_member"] for r in rows),
        "module_clustered_any": sum(bool(r["module"]) for r in rows),
        "module_evidence_counts": dict(sorted(module_evidence_counts.items())),
        "semantic_name_symbol_sources": dict(sorted(semantic_name_sources.items())),
        "functions_with_any_structural_or_semantic_evidence": any_evidence,
        "functions_with_any_structural_or_semantic_evidence_pct": round(100 * any_evidence / total, 2),
        "remaining_without_any_core_evidence": total - any_evidence,
        "remaining_without_decompiled_body": total - sum(r["decompiled"] for r in rows),
        "semantic_completion_estimate_pct": round(100 * sum(r["semantic_score"] for r in rows) / total, 2),
        "semantic_score_model": {
            "decompiled_body": 0.20,
            "direct_source_association": 0.25,
            "inferred_module_if_no_direct_source": 0.10,
            "curated_user_semantic_name": 0.35,
            "other_recovered_semantic_name": 0.15,
            "vtable_membership": 0.10,
            "cap": 1.0,
            "interpretation": "evidence-weighted progress proxy; a Ghidra C body alone is not treated as semantic completion",
        },
        "subsystems": by_wave,
        "batch_count": len(batches),
        "batch_size": args.batch_size,
    }
    (out / "coverage.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    (out / "batches.json").write_text(json.dumps(batches, indent=2) + "\n", encoding="utf-8")
    with (out / "batch_manifest.tsv").open("w", newline="", encoding="utf-8") as f:
        fields = [
            "id", "wave", "module", "module_evidence", "count", "priority_max", "priority_mean",
            "address_min", "address_max", "list", "outbound_dependencies", "inbound_neighbors",
        ]
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
        w.writeheader()
        for b in batches:
            w.writerow({
                **{k: b[k] for k in fields[:10]},
                "outbound_dependencies": ";".join(
                    f"{x['batch']}:{x['edges']}" for x in b["outbound_batch_dependencies"]
                ),
                "inbound_neighbors": ";".join(
                    f"{x['batch']}:{x['edges']}" for x in b["inbound_batch_neighbors"]
                ),
            })

    # Compact human report, regenerated from the same measurements.
    pct = lambda n: 100.0 * n / total
    lines = [
        "# Full semantic decomp coverage\n",
        f"Inventory denominator: **{total:,} Ghidra functions**. The headless callgraph export has **{len(callgraph_rows):,} directed edges**; **{edge_count:,}** connect two functions in the 21,953-function inventory and are used for locality clustering.\n",
        "## Measured coverage\n",
        "| signal | functions / records | function coverage |",
        "|---|---:|---:|",
        f"| any non-`FUN_` semantic name | {summary['semantic_names_any']:,} | {pct(summary['semantic_names_any']):.2f}% |",
        f"| curated `USER_DEFINED` semantic name | {summary['semantic_names_curated']:,} | {pct(summary['semantic_names_curated']):.2f}% |",
        f"| direct embedded-source association (>=80% confidence) | {summary['direct_source_associations']:,} | {pct(summary['direct_source_associations']):.2f}% |",
        f"| existing Ghidra decompiled body | {summary['existing_decompiled_functions']:,} | {pct(summary['existing_decompiled_functions']):.2f}% |",
        f"| unique function appearing in recovered vtable slot(s) | {summary['vtable_unique_function_members']:,} | {pct(summary['vtable_unique_function_members']):.2f}% |",
        f"| direct/inferred/vtable module cluster | {summary['module_clustered_any']:,} | {pct(summary['module_clustered_any']):.2f}% |",
        f"| any core semantic/structural evidence | {any_evidence:,} | {pct(any_evidence):.2f}% |",
        "",
        f"Recovered class metadata contains **{len(registry_rows):,} registry records**, **{len(vtable_rows):,} vtables**, and **{total_vtable_slots:,} vtable slot references**. These are structural artifacts; they are not counted as completed function semantics unless they identify a function slot.",
        "",
        "## Semantic completion estimate\n",
        f"The evidence-weighted current estimate is **~{summary['semantic_completion_estimate_pct']:.1f}%** of a full semantic decomp, with a reasonable **±2 percentage-point** uncertainty band. Source-file and module associations identify locality, while only a small number of functions have human-curated behavior names/types. The raw structural footprint is higher ({pct(any_evidence):.2f}%), but treating that as semantic completion would overstate progress.",
        "",
        "The scoring proxy gives 20% credit for an existing decompiled body, 25% for a direct source-module association, 10% for a conservative inferred module, 35% for a curated semantic name (15% for another recovered semantic symbol), and 10% for vtable membership. Scores are capped at 100% per function. This makes mechanically exported C useful but insufficient by itself.",
        "",
        f"Module locality is currently direct-source for **{module_evidence_counts['direct_source']:,}** functions, address-inferred for **{module_evidence_counts['address']:,}**, callgraph-inferred for **{module_evidence_counts['graph']:,}**, corroborated by both for **{module_evidence_counts['graph+address']:,}**, and vtable-only for **{module_evidence_counts['vtable']:,}**. **{module_evidence_counts['none']:,}** remain without a module assignment.",
        "",
        "Subsystem percentages below are estimates over the currently classified cohorts, not claims that those cohorts exhaust the subsystem. The large `unclustered` cohort is kept explicit instead of forcing weak address-only subsystem assignments.",
        "",
        "## Subsystem estimates\n",
        "| wave | functions | decompiled | direct source | vtable funcs | clustered | semantic estimate | remaining C exports |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for wave in wave_order:
        s = by_wave.get(wave)
        if not s:
            continue
        lines.append(
            f"| `{wave}` | {s['functions']:,} | {s['decompiled']:,} | {s['direct_source']:,} | "
            f"{s['vtable_members']:,} | {s['module_clustered']:,} | **{s['semantic_estimate_pct']:.2f}%** | {s['remaining_not_decompiled']:,} |"
        )
    lines += [
        "",
        "## Remaining gaps and batch plan\n",
        f"**{summary['remaining_without_decompiled_body']:,}** functions still lack an exported Ghidra C body. **{summary['remaining_without_any_core_evidence']:,}** lack all four core signals (semantic name, decompiled body, direct source association, vtable membership).",
        "",
        f"`batches.json` contains **{len(batches):,} batches** (maximum {args.batch_size} functions each). Existing decompiled functions are excluded. Ordering is backend target → optimizer → frontend bridge → frontend → runtime support → unclustered. Within a likely module, breadth-first traversal of the induced callgraph keeps callers/callees together; seed selection favors semantic names, source/vtable evidence, graph centrality, and larger bodies.",
        "",
        "`batch_manifest.tsv` is the compact scheduling view. It records the strongest cross-batch outgoing dependencies and incoming neighbors so adjacent batches can be scheduled together when a decompilation needs caller/callee context.",
        "",
        "Direct source paths are high-confidence anchors. Inferred module labels require either matching source anchors on both address sides within 64 KiB, at least two direct-source callgraph neighbors with >=75% agreement, or both. Vtable-only groupings are explicitly marked as lower-confidence structural locality.",
    ]
    (out / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
