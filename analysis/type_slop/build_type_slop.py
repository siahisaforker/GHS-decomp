#!/usr/bin/env python3
"""Aggressive type/virtual-method propagation for GHS ecomppc.exe.

Consumes the recovered custom class registry, vtables, full Ghidra function
inventory/callgraph, and optional exact Ghidra references to vptr addresses.
Outputs confidence-tagged hypotheses only; it never renames the Ghidra DB.
"""

from __future__ import annotations

import argparse
import bisect
import csv
import json
import re
import struct
from collections import Counter, defaultdict, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REGISTRY = ROOT / "analysis/worker3_static_map/ghs_registry.tsv"
VTABLES = ROOT / "analysis/worker3_static_map/ghs_vtables.tsv"
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
CALLGRAPH = ROOT / "analysis/full_decomp/callgraph.tsv"
VPTR_REFS = HERE / "vptr_refs.tsv"
VPTR_STORE_REFS = HERE / "vptr_store_refs.tsv"
EXE = ROOT / "ghs5.3.22/bin/ecomppc.exe"

SLOT_RE = re.compile(r"([+-]\d+):0x([0-9a-fA-F]{8})")
DEFAULT_FUN = re.compile(r"FUN_[0-9A-Fa-f]+$")


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def write_tsv(path: Path, rows: list[dict], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t", lineterminator="\n", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def parse_slots(text: str) -> list[tuple[int, int]]:
    return [(int(a), int(v, 16)) for a, v in SLOT_RE.findall(text)]


def slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_]+", "_", name).strip("_")
    return re.sub(r"_+", "_", s) or "anon"


def raw_vtable_header_refs(vtables: list[dict[str, str]], funcs: dict[str, dict[str, str]]) -> list[dict]:
    """Find immediate references to custom vtable headers inside .text.

    GHS constructors in this binary store table_header_va itself in the object.
    Ghidra did not promote these scalar immediates into references, so a raw
    exact-immediate scan is both reproducible and necessary.
    """
    data = EXE.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    st = opt + optsz
    text = None
    for i in range(nsec):
        p = st + 40 * i
        name = data[p:p+8].split(b"\0",1)[0]
        vsize, rva, rawsz, rawoff = struct.unpack_from("<IIII", data, p + 8)
        if name == b".text":
            text = (rva, vsize, rawsz, rawoff)
            break
    if text is None:
        raise RuntimeError(".text not found")
    rva, vsize, rawsz, rawoff = text
    blob = data[rawoff:rawoff + rawsz]
    text_va = image_base + rva

    intervals = sorted((int(r["body_min"],16), int(r["body_max"],16), a) for a,r in funcs.items())
    starts = [x[0] for x in intervals]
    def containing(va: int) -> str:
        i = bisect.bisect_right(starts, va) - 1
        if i >= 0 and intervals[i][0] <= va <= intervals[i][1]:
            return intervals[i][2]
        return ""

    rows = []
    for vr in vtables:
        header = int(vr["table_header_va"], 16)
        needle = struct.pack("<I", header)
        pos = 0
        while True:
            hit = blob.find(needle, pos)
            if hit < 0:
                break
            pos = hit + 1
            imm_va = text_va + hit
            fn = containing(imm_va)
            if not fn:
                continue
            abs_off = rawoff + hit
            before = data[max(0, abs_off-8):abs_off]
            op = data[abs_off-1] if abs_off else 0
            form, conf = "raw_imm32", 0.72
            if 0xB8 <= op <= 0xBF:
                form, conf = "mov_reg_imm32", 0.95
            elif op == 0x68:
                form, conf = "push_imm32", 0.78
            elif 0xC7 in before[-7:]:
                form, conf = "mov_mem_imm32", 0.90
            rows.append({
                "record_va": vr["record_va"].lower(),
                "class_name": vr["name"],
                "table_header_va": vr["table_header_va"].lower(),
                "vptr_va": vr["vptr_va"].lower(),
                "immediate_va": f"{imm_va:08x}",
                "function_entry": fn,
                "function_name": funcs[fn]["name"],
                "instruction_form": form,
                "confidence": f"{conf:.2f}",
            })
    return sorted(rows, key=lambda r: (r["function_entry"], r["immediate_va"], r["record_va"]))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=HERE)
    ap.add_argument("--graph-depth", type=int, default=2)
    args = ap.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)

    registry = read_tsv(REGISTRY)
    vtables = read_tsv(VTABLES)
    funcs = {r["entry"].lower(): r for r in read_tsv(FUNCTIONS)}
    call_rows = read_tsv(CALLGRAPH)
    raw_header_rows = raw_vtable_header_refs(vtables, funcs)

    reg_by_va = {r["record_va"].lower(): r for r in registry}
    by_name = defaultdict(list)
    for r in registry:
        by_name[r["name"]].append(r)
    vt_by_record = {r["record_va"].lower(): r for r in vtables}

    # Inheritance forest: the descriptor gives a primary base record directly.
    base_of: dict[str, str] = {}
    children: dict[str, list[str]] = defaultdict(list)
    for r in registry:
        child = r["record_va"].lower()
        base = r["primary_base_record_va"].lower()
        if base and base in reg_by_va:
            base_of[child] = base
            children[base].append(child)

    def lineage(va: str) -> list[str]:
        seen, path = set(), []
        cur = va
        while cur and cur not in seen and cur in reg_by_va:
            seen.add(cur)
            path.append(cur)
            cur = base_of.get(cur, "")
        return path

    def root_of(va: str) -> str:
        p = lineage(va)
        return p[-1] if p else va

    def depth_of(va: str) -> int:
        return max(0, len(lineage(va)) - 1)

    groups: dict[str, list[str]] = defaultdict(list)
    for va in reg_by_va:
        groups[root_of(va)].append(va)

    group_rows = []
    group_id_of: dict[str, str] = {}
    for root, members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        root_name = reg_by_va[root]["name"]
        gid = f"{slug(root_name)}@{root}"
        for m in members:
            group_id_of[m] = gid
        cats = Counter(reg_by_va[m]["category"] for m in members)
        group_rows.append({
            "group_id": gid,
            "root_record_va": root,
            "root_name": root_name,
            "member_count": len(members),
            "max_depth": max(depth_of(m) for m in members),
            "categories": ";".join(f"{k}:{v}" for k, v in cats.most_common()),
            "members": ";".join(f"{reg_by_va[m]['name']}@{m}" for m in sorted(members)),
        })

    hierarchy_rows = []
    for r in registry:
        va = r["record_va"].lower()
        base = base_of.get(va, "")
        hierarchy_rows.append({
            "record_va": va,
            "class_name": r["name"],
            "category": r["category"],
            "group_id": group_id_of[va],
            "depth": depth_of(va),
            "primary_base_record_va": base,
            "primary_base_name": reg_by_va[base]["name"] if base else "",
            "has_vtable": "1" if va in vt_by_record else "0",
            "vptr_va": vt_by_record.get(va, {}).get("vptr_va", ""),
            "slot_count": vt_by_record.get(va, {}).get("slot_count", "0"),
            "confidence": "0.99" if base else "0.95",
            "evidence": "descriptor_primary_base" if base else "registry_root",
        })

    # Slot relation to immediate base. This creates stable family+slot semantic IDs.
    slot_rows = []
    direct_method_classes: dict[str, set[str]] = defaultdict(set)
    direct_method_records: dict[str, set[str]] = defaultdict(set)
    direct_method_slots: dict[str, set[str]] = defaultdict(set)
    direct_method_groups: dict[str, set[str]] = defaultdict(set)
    direct_method_relations: dict[str, Counter] = defaultdict(Counter)
    for vr in vtables:
        rec = vr["record_va"].lower()
        cls = vr["name"]
        slots = parse_slots(vr["slots"])
        base = base_of.get(rec, "")
        bslots = parse_slots(vt_by_record[base]["slots"]) if base in vt_by_record else []
        root = root_of(rec)
        family = reg_by_va[root]["name"]
        for i, (adjust, fn) in enumerate(slots):
            faddr = f"{fn:08x}"
            relation = "root_or_new"
            base_fn = ""
            if i < len(bslots):
                base_fn = f"{bslots[i][1]:08x}"
                relation = "inherited" if bslots[i][1] == fn and bslots[i][0] == adjust else "override"
            semantic_id = f"{slug(family)}.slot_{i:03d}"
            proposed = f"{slug(cls)}__vslot_{i:03d}"
            if relation == "inherited":
                conf = 0.93
            elif relation == "override":
                conf = 0.90
            else:
                conf = 0.78
            slot_rows.append({
                "record_va": rec,
                "class_name": cls,
                "group_id": group_id_of[rec],
                "vptr_va": vr["vptr_va"].lower(),
                "slot": i,
                "this_adjust": adjust,
                "function_entry": faddr,
                "function_name": funcs.get(faddr, {}).get("name", ""),
                "base_record_va": base,
                "base_class_name": reg_by_va[base]["name"] if base else "",
                "base_function_entry": base_fn,
                "relation": relation,
                "semantic_slot_id": semantic_id,
                "proposed_name": proposed,
                "confidence": f"{conf:.2f}",
            })
            if faddr in funcs:
                direct_method_classes[faddr].add(cls)
                direct_method_records[faddr].add(rec)
                direct_method_slots[faddr].add(semantic_id)
                direct_method_groups[faddr].add(group_id_of[rec])
                direct_method_relations[faddr][relation] += 1

    # Exact memory-store xrefs are strongest. Operand/immediate sightings add
    # breadth. Collapse duplicate function/class pairs across evidence sources
    # so the same table found twice does not manufacture a fake write sequence.
    vptr_rows = read_tsv(VPTR_REFS) if VPTR_REFS.exists() else []
    store_rows = read_tsv(VPTR_STORE_REFS) if VPTR_STORE_REFS.exists() else []
    init_by_func: dict[str, list[dict[str, str]]] = defaultdict(list)
    init_pairs: set[tuple[str, str]] = set()
    usable_vptr_rows = 0
    for r in store_rows:
        a = r.get("function_entry", "").lower()
        rec = r.get("record_va", "").lower()
        if a in funcs and rec in reg_by_va and (a, rec) not in init_pairs:
            init_by_func[a].append(r)
            init_pairs.add((a, rec))
    for r in vptr_rows:
        if r.get("literal_kind") and r.get("literal_kind") != "table_header":
            continue
        a = r.get("function_entry", "").lower()
        rec = r.get("record_va", "").lower()
        if a in funcs:
            usable_vptr_rows += 1
        if a in funcs and rec in reg_by_va and (a, rec) not in init_pairs:
            init_by_func[a].append(r)
            init_pairs.add((a, rec))
    for r in raw_header_rows:
        a = r["function_entry"].lower()
        rec = r["record_va"].lower()
        if a in funcs and rec in reg_by_va and (a, rec) not in init_pairs:
            init_by_func[a].append(r)
            init_pairs.add((a, rec))

    # Seed known backend constructor established by prior backend mapping.
    seeded_roles = {
        "00424ceb": ("backend_t", "constructor", 0.99, "backend_map curated anchor; allocates target object and installs backend_t vptr"),
    }

    # Directed and undirected call graph for class-association propagation.
    graph: dict[str, set[str]] = defaultdict(set)
    callers: dict[str, set[str]] = defaultdict(set)
    callees: dict[str, set[str]] = defaultdict(set)
    for r in call_rows:
        a, b = r["caller_addr"].lower(), r["callee_addr"].lower()
        if a not in funcs or b not in funcs:
            continue
        graph[a].add(b); graph[b].add(a)
        callees[a].add(b); callers[b].add(a)

    hypotheses: dict[str, dict] = {}

    def offer(addr: str, role: str, label: str, conf: float, classes=(), groups_=(), evidence=(), slots=()):
        if addr not in funcs:
            return
        cur = hypotheses.get(addr)
        ev = list(evidence)
        item = {
            "function_entry": addr,
            "current_name": funcs[addr]["name"],
            "proposed_name": label,
            "role": role,
            "confidence": round(conf, 3),
            "classes": set(classes),
            "groups": set(groups_),
            "semantic_slots": set(slots),
            "evidence": ev,
        }
        if cur is None or conf > cur["confidence"]:
            hypotheses[addr] = item
        else:
            cur["classes"].update(classes)
            cur["groups"].update(groups_)
            cur["semantic_slots"].update(slots)
            cur["evidence"].extend(x for x in ev if x not in cur["evidence"])

    for addr in direct_method_classes:
        classes = sorted(direct_method_classes[addr])
        groups_ = sorted(direct_method_groups[addr])
        slots = sorted(direct_method_slots[addr])
        rels = direct_method_relations[addr]
        if len(classes) == 1 and len(slots) == 1:
            label = f"{slug(classes[0])}__{slug(slots[0].split('.')[-1])}"
            conf = 0.91 if rels["override"] else 0.84
        elif len(groups_) == 1 and len(slots) == 1:
            label = f"{slug(groups_[0].split('@')[0])}__{slug(slots[0].split('.')[-1])}_shared"
            conf = 0.82
        else:
            label = f"virtual_method_shared_{addr}"
            conf = 0.70
        offer(addr, "virtual_method", label, conf, classes, groups_, [f"vtable_membership:{len(classes)} classes"], slots)

    for addr, refs in init_by_func.items():
        classes = sorted({r["class_name"] for r in refs})
        records = sorted({r["record_va"].lower() for r in refs if r["record_va"].lower() in reg_by_va})
        groups_ = sorted({group_id_of[r] for r in records})
        ordered = [r["record_va"].lower() for r in sorted(refs, key=lambda r: int(r.get("instruction_va") or r.get("immediate_va") or r.get("xref_from") or "0", 16)) if r["record_va"].lower() in reg_by_va]
        compressed = []
        for rec in ordered:
            if not compressed or compressed[-1] != rec:
                compressed.append(rec)
        repeated = len(ordered) != len(set(ordered))
        body_size = int(funcs[addr]["body_size"])
        compact = body_size <= 1500 and len(refs) <= 8 and len(records) <= 4 and len(groups_) <= 1
        role = "typed_object_initialization_site"
        label = f"typed_init_site_{addr}"
        store_count = sum(float(r.get("confidence", "0") or 0) >= 0.98 for r in refs)
        conf = 0.74 if store_count else (0.68 if usable_vptr_rows else 0.56)
        if compact and not repeated and len(compressed) >= 2:
            first, last = compressed[0], compressed[-1]
            ctor_chain = all(a in lineage(b)[1:] for a, b in zip(compressed, compressed[1:]))
            dtor_chain = all(b in lineage(a)[1:] for a, b in zip(compressed, compressed[1:]))
            if ctor_chain and first in lineage(last)[1:]:
                role = "constructor_like"
                label = f"{slug(reg_by_va[last]['name'])}__ctor_candidate"
                conf = 0.92
            elif dtor_chain and last in lineage(first)[1:]:
                role = "destructor_like"
                label = f"{slug(reg_by_va[first]['name'])}__dtor_candidate"
                conf = 0.88
        elif compact and not repeated and len(records) == 1:
            role = "constructor_or_destructor_like"
            label = f"{slug(reg_by_va[records[0]]['name'])}__vtable_initializer_candidate"
            conf = 0.80
        offer(addr, role, label, conf, classes, groups_, [f"direct_vtable_header_or_vptr_refs:{len(refs)}", f"store_backed:{store_count}", "write_order:" + ">".join(reg_by_va[x]["name"] for x in ordered)])

    # A derived constructor may only write its own table and delegate base
    # setup to a direct callee.  Promote those when the callee writes the
    # immediate base class table; this captures the resource scheduler ctors.
    init_records = {
        a: {r["record_va"].lower() for r in rr if r["record_va"].lower() in reg_by_va}
        for a, rr in init_by_func.items()
    }
    for addr, recs in init_records.items():
        if len(recs) != 1:
            continue
        rec = next(iter(recs))
        base = base_of.get(rec, "")
        if not base:
            continue
        base_ctor = next((c for c in callees.get(addr, ()) if base in init_records.get(c, set())), "")
        if not base_ctor:
            continue
        cls = reg_by_va[rec]["name"]
        offer(addr, "constructor_like", f"{slug(cls)}__ctor_candidate", 0.93,
              [cls], [group_id_of[rec]],
              [f"writes_own_vtable:{vt_by_record.get(rec, {}).get('table_header_va', '')}",
               f"calls_base_initializer:{base_ctor}:{reg_by_va[base]['name']}"])

    # Verified GHS std::* ABI pattern: slot 0 is a scalar-deleting destructor
    # when it calls 0x005b974d.  std::exception @ 0x00405190 is the concrete
    # anchor (tests a delete flag, then calls that deallocator helper).
    for sr in slot_rows:
        if int(sr["slot"]) != 0:
            continue
        rec = sr["record_va"]
        if reg_by_va[rec]["category"] != "runtime/std":
            continue
        addr = sr["function_entry"]
        if addr not in funcs or "005b974d" not in callees.get(addr, set()):
            continue
        cls = sr["class_name"]
        offer(addr, "destructor_like", f"{slug(cls)}__scalar_deleting_dtor", 0.95,
              [cls], [group_id_of[rec]],
              ["runtime_std_slot0", "calls_deallocator_005b974d", "verified_std_exception_pattern"])

    for addr, (cls, role, conf, ev) in seeded_roles.items():
        records = [r["record_va"].lower() for r in by_name.get(cls, [])]
        offer(addr, role, f"{slug(cls)}__ctor", conf, [cls], [group_id_of[r] for r in records], [ev])

    # Propagate class/group association through call neighborhoods. Direct type
    # anchors vote; one hop is useful, two hops is deliberately lower confidence.
    anchor_groups = {a: set(direct_method_groups[a]) for a in direct_method_groups}
    for a, refs in init_by_func.items():
        for r in refs:
            rec = r["record_va"].lower()
            if rec in group_id_of:
                anchor_groups.setdefault(a, set()).add(group_id_of[rec])

    vote_accum: dict[str, Counter] = defaultdict(Counter)
    vote_sources: dict[tuple[str, str], set[str]] = defaultdict(set)
    for src, gs in anchor_groups.items():
        q = deque([(src, 0)])
        seen = {src}
        while q:
            cur, d = q.popleft()
            if d >= args.graph_depth:
                continue
            for nxt in graph.get(cur, ()):
                if nxt in seen:
                    continue
                seen.add(nxt)
                nd = d + 1
                weight = 4 if nd == 1 else 1
                for g in gs:
                    vote_accum[nxt][g] += weight
                    vote_sources[(nxt, g)].add(src)
                q.append((nxt, nd))

    for addr, votes in vote_accum.items():
        if addr in direct_method_classes or addr in init_by_func:
            continue
        if not DEFAULT_FUN.fullmatch(funcs[addr]["name"]):
            continue
        total = sum(votes.values())
        group, score = votes.most_common(1)[0]
        dominance = score / total if total else 0
        sources = vote_sources[(addr, group)]
        if score < 2 or dominance < 0.60:
            continue
        root_name = group.split("@", 1)[0]
        conf = min(0.76, 0.42 + 0.04 * score + 0.05 * min(len(sources), 3))
        direction = "caller_or_callee"
        direct_neighbors = graph.get(addr, set())
        if any(s in callers.get(addr, set()) for s in sources & direct_neighbors):
            direction = "called_by_typed_method"
        if any(s in callees.get(addr, set()) for s in sources & direct_neighbors):
            direction = "calls_typed_method" if direction == "caller_or_callee" else "bidirectional_typed_neighborhood"
        offer(addr, "class_associated_helper", f"{slug(root_name)}__helper_{addr}", conf, [], [group], [f"callgraph_vote:{score}/{total}", f"typed_sources:{len(sources)}", direction])

    # Flatten output.
    hyp_rows = []
    for addr, h in sorted(hypotheses.items(), key=lambda kv: (-kv[1]["confidence"], kv[0])):
        hyp_rows.append({
            "function_entry": addr,
            "current_name": h["current_name"],
            "proposed_name": h["proposed_name"],
            "role": h["role"],
            "confidence": f"{h['confidence']:.3f}",
            "classes": ";".join(sorted(h["classes"])),
            "groups": ";".join(sorted(h["groups"])),
            "semantic_slots": ";".join(sorted(h["semantic_slots"])),
            "evidence": ";".join(h["evidence"]),
            "caller_count": len(callers.get(addr, ())),
            "callee_count": len(callees.get(addr, ())),
            "body_size": funcs[addr]["body_size"],
        })

    backend_names = {"backend_dataflow", "backend_basetype", "backend_basetype2", "backend_t"}
    backend_records = {r["record_va"].lower() for r in registry if r["name"] in backend_names}
    backend_hierarchy = [r for r in hierarchy_rows if r["record_va"] in backend_records]
    backend_slots = [r for r in slot_rows if r["record_va"] in backend_records]

    semantic_groups: dict[str, list[dict]] = defaultdict(list)
    for row in slot_rows:
        semantic_groups[row["semantic_slot_id"]].append(row)
    semantic_rows = []
    for sid, rows in sorted(semantic_groups.items()):
        targets = Counter(r["function_entry"] for r in rows)
        rels = Counter(r["relation"] for r in rows)
        top_target, top_count = targets.most_common(1)[0]
        fraction = top_count / len(rows)
        if fraction >= 0.75:
            hint, conf = "shared_implementation", 0.82
        elif rels["override"] > rels["inherited"]:
            hint, conf = "override_heavy", 0.72
        else:
            hint, conf = "family_virtual_slot", 0.62
        semantic_rows.append({
            "semantic_slot_id": sid,
            "slot": rows[0]["slot"],
            "classes": len({r["class_name"] for r in rows}),
            "class_names": ";".join(sorted({r["class_name"] for r in rows})),
            "unique_targets": len(targets),
            "dominant_target": top_target,
            "dominant_target_count": top_count,
            "dominant_fraction": f"{fraction:.3f}",
            "inherited": rels["inherited"],
            "overrides": rels["override"],
            "introduced_or_root": rels["root_or_new"],
            "semantic_hint": hint,
            "confidence": f"{conf:.2f}",
        })

    constructor_rows = [
        r for r in hyp_rows
        if r["role"] in {
            "constructor", "constructor_like", "destructor_like",
            "constructor_or_destructor_like", "typed_object_initialization_site",
        }
    ]
    rename_rows = []
    for r in hyp_rows:
        conf = float(r["confidence"])
        direct_role = r["role"] in {"virtual_method", "constructor", "constructor_like", "destructor_like"}
        if direct_role and conf >= 0.85 and DEFAULT_FUN.fullmatch(r["current_name"]):
            rr = dict(r)
            rr["tier"] = "direct_apply_candidate"
            rename_rows.append(rr)

    write_tsv(out / "class_groups.tsv", group_rows, ["group_id","root_record_va","root_name","member_count","max_depth","categories","members"])
    write_tsv(out / "hierarchy.tsv", hierarchy_rows, ["record_va","class_name","category","group_id","depth","primary_base_record_va","primary_base_name","has_vtable","vptr_va","slot_count","confidence","evidence"])
    write_tsv(out / "virtual_slots.tsv", slot_rows, ["record_va","class_name","group_id","vptr_va","slot","this_adjust","function_entry","function_name","base_record_va","base_class_name","base_function_entry","relation","semantic_slot_id","proposed_name","confidence"])
    write_tsv(out / "function_hypotheses.tsv", hyp_rows, ["function_entry","current_name","proposed_name","role","confidence","classes","groups","semantic_slots","evidence","caller_count","callee_count","body_size"])
    write_tsv(out / "backend_hierarchy.tsv", backend_hierarchy, ["record_va","class_name","category","group_id","depth","primary_base_record_va","primary_base_name","has_vtable","vptr_va","slot_count","confidence","evidence"])
    write_tsv(out / "backend_slots.tsv", backend_slots, ["record_va","class_name","group_id","vptr_va","slot","this_adjust","function_entry","function_name","base_record_va","base_class_name","base_function_entry","relation","semantic_slot_id","proposed_name","confidence"])
    write_tsv(out / "vtable_header_refs.tsv", raw_header_rows, ["record_va","class_name","table_header_va","vptr_va","immediate_va","function_entry","function_name","instruction_form","confidence"])
    write_tsv(out / "slot_semantics.tsv", semantic_rows, ["semantic_slot_id","slot","classes","class_names","unique_targets","dominant_target","dominant_target_count","dominant_fraction","inherited","overrides","introduced_or_root","semantic_hint","confidence"])
    write_tsv(out / "constructor_candidates.tsv", constructor_rows, ["function_entry","current_name","proposed_name","role","confidence","classes","groups","semantic_slots","evidence","caller_count","callee_count","body_size"])
    write_tsv(out / "rename_candidates.tsv", rename_rows, ["function_entry","current_name","proposed_name","role","confidence","tier","classes","groups","semantic_slots","evidence","caller_count","callee_count","body_size"])

    summary = {
        "registry_records": len(registry),
        "unique_class_names": len(by_name),
        "primary_base_links": len(base_of),
        "class_groups": len(groups),
        "vtables": len(vtables),
        "vtable_classes": len({r["name"] for r in vtables}),
        "virtual_slot_entries": len(slot_rows),
        "unique_virtual_functions": len(direct_method_classes),
        "vptr_xref_rows": len(vptr_rows),
        "store_backed_vptr_refs": len(store_rows),
        "decoded_vtable_header_refs": usable_vptr_rows,
        "raw_vtable_header_refs": len(raw_header_rows),
        "vptr_initializer_class_pairs": len(init_pairs),
        "vptr_initializer_functions": len(init_by_func),
        "shared_slot_semantics": len(semantic_rows),
        "function_hypotheses": len(hyp_rows),
        "hypothesis_roles": Counter(r["role"] for r in hyp_rows),
        "confidence_bands": {
            "high_ge_0_85": sum(float(r["confidence"]) >= 0.85 for r in hyp_rows),
            "medium_0_65_to_0_849": sum(0.65 <= float(r["confidence"]) < 0.85 for r in hyp_rows),
            "slop_lt_0_65": sum(float(r["confidence"]) < 0.65 for r in hyp_rows),
        },
        "backend_chain": [
            {"class": r["class_name"], "record_va": r["record_va"], "base": r["primary_base_name"], "slots": int(r["slot_count"])}
            for r in sorted(backend_hierarchy, key=lambda x: int(x["depth"]))
        ],
        "backend_slot_relations": dict(Counter(r["relation"] for r in backend_slots)),
    }
    # Counter is JSON-compatible only after conversion.
    summary["hypothesis_roles"] = dict(summary["hypothesis_roles"])
    (out / "type_map.json").write_text(json.dumps({
        "summary": summary,
        "groups": group_rows,
        "hierarchy": hierarchy_rows,
        "virtual_slots": slot_rows,
        "slot_semantics": semantic_rows,
        "backend_hierarchy": backend_hierarchy,
        "backend_slots": backend_slots,
        "constructor_candidates": constructor_rows,
        "rename_candidates": rename_rows,
        "function_hypotheses": hyp_rows,
    }, indent=2) + "\n", encoding="utf-8")
    (out / "backend_map.json").write_text(json.dumps({
        "hierarchy": backend_hierarchy,
        "slots": backend_slots,
        "constructor": next((r for r in rename_rows if r["function_entry"] == "00424ceb"), None),
    }, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
