#!/usr/bin/env python3
"""Generate aggressive, evidence-preserving semantic name proposals for ecomppc.exe.

This is intentionally a proposal pass.  It never edits the Ghidra project.
"""

from __future__ import annotations

import csv
import glob
import hashlib
import json
import math
import os
import re
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
SOURCE_MAP = ROOT / "analysis/prime/source_file_function_map.tsv"
STRING_XREFS = ROOT / "analysis/ghidra/out/all_string_xrefs.tsv"
CALLGRAPH = ROOT / "analysis/full_decomp/callgraph.tsv"
VTABLES = ROOT / "analysis/worker3_static_map/ghs_vtables.tsv"
REGISTRY = ROOT / "analysis/worker3_static_map/ghs_registry.tsv"
BACKEND_FUNCTIONS = ROOT / "analysis/backend_map/function_map.csv"
OPTION_GLOBALS = ROOT / "analysis/backend_map/option_globals.csv"
DECOMP_GLOBS = [
    "analysis/full_decomp/exports_wave/**/*.c",
    "analysis/ghidra/out/decompiled/*.c",
    "analysis/ghidra/out/keypasses/**/*.c",
    "analysis/ghidra/out/resource_scheduler/**/*.c",
    "analysis/ppc_emitter/decompiled_output/*.c",
]

DEFAULT_NAME = re.compile(r"FUN_[0-9A-Fa-f]+$")
ADDR = re.compile(r"0x([0-9A-Fa-f]{8})")
DECOMP_ADDR = re.compile(r"([0-9A-Fa-f]{8})_")

STOP = {
    "the", "and", "for", "from", "with", "this", "that", "into", "not", "null", "true", "false",
    "error", "warning", "failed", "failure", "unexpected", "invalid", "cannot", "unable", "internal",
    "file", "line", "number", "value", "type", "name", "found", "current", "expected", "compiler",
    "before", "after", "using", "used", "when", "while", "where", "should", "would", "could", "only",
    "option", "options", "argument", "arguments", "function", "routine", "object", "program", "source",
}

ROLE_RULES = [
    ("register_allocator", ("allocreg", "register allocation", "coalesce", "spill", "coloring", "interference graph")),
    ("scheduler", ("schedule", "scheduler", "pipeline", "issue group", "latency", "resource scheduler")),
    ("dataflow", ("dataflow", "dflow", "liveness", "live range", "value numbering", "vn_", "reaching")),
    ("branch_optimizer", ("branch", "basic block", "successor", "predecessor", "fallthrough")),
    ("loop_optimizer", ("loop", "induction", "unroll", "loop invariant")),
    ("alias_analysis", ("alias", "points-to", "points to")),
    ("vectorizer", ("vectorize", "vectorization", "simd vector", "simd_vector")),
    ("instruction_encoder", ("opcode", "operand", "instruction", "encoding", "relocation", "reloc", "vector operation", "vector write", "vector read")),
    ("assembler", ("assembler", "assembly", "mnemonic", "register name", "asm")),
    ("object_emitter", ("elf", "section", "symbol table", "object file", "emit", "codewrite", "output section")),
    ("debug_emitter", ("dwarf", "debug info", "debugging", "line table", "stabs")),
    ("pragma_parser", ("pragma", "directive")),
    ("lexer", ("lexer", "lexical", "token", "scanner")),
    ("parser", ("parse", "parser", "syntax", "declarator", "expression")),
    ("template_semantics", ("template", "instantiation", "specialization")),
    ("class_semantics", ("class", "base class", "virtual function", "overload", "constructor", "destructor")),
    ("type_system", ("type qualifier", "typedef", "type conversion", "type information")),
    ("inline_optimizer", ("inline", "inlining")),
    ("constant_folder", ("constant fold", "folding", "constant propagation", "propagate constants")),
    ("diagnostic", ("diagnostic", "fatal error", "warning", "error #", "internal compiler error")),
    ("memory_manager", ("heap", "malloc", "allocate memory", "out of memory", "memory block")),
]


def read_table(path: Path, delimiter="\t") -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f, delimiter=delimiter))


def clean_ident(text: str, max_len: int = 72) -> str:
    text = text.replace("::", "_")
    text = re.sub(r"[^A-Za-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    if not text:
        return "unknown"
    if text[0].isdigit():
        text = "n_" + text
    return text[:max_len].rstrip("_")


def norm_va(text: str) -> str:
    return f"0x{int(text.removeprefix('0x'), 16):08x}"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sha256_decomp(paths: list[Path]) -> str:
    h = hashlib.sha256()
    for p in sorted(paths):
        h.update(str(p.relative_to(ROOT)).encode())
        h.update(b"\0")
        h.update(bytes.fromhex(sha256_file(p)))
    return h.hexdigest()


def module_from_source(path: str) -> str:
    base = os.path.basename(path.replace("\\", "/"))
    stem = base.rsplit(".", 1)[0]
    return clean_ident(stem.lower(), 36)


def role_hits(text: str) -> Counter:
    low = text.lower()
    out = Counter()
    for role, needles in ROLE_RULES:
        for needle in needles:
            if needle in low:
                out[role] += 1
    return out


def phrase_from_string(text: str) -> tuple[str, float]:
    """Turn a diagnostic/trace string into a short searchable semantic phrase."""
    raw = text.strip()
    if not raw or len(raw) < 4:
        return "", 0.0
    if re.search(r"[/\\][A-Za-z0-9_.-]+[/\\]", raw):
        return "", 0.0
    if raw.startswith(("http://", "https://")):
        return "", 0.0
    cleaned = re.sub(r"%[-+ #0-9.*hlLjztI]*[A-Za-z%]", " ", raw)
    cleaned = re.sub(r"0x[0-9A-Fa-f]+", " ", cleaned)
    toks = [t.lower() for t in re.findall(r"[A-Za-z][A-Za-z0-9_+-]{2,}", cleaned)]
    useful = [t for t in toks if t not in STOP and not t.startswith("__")]
    if not useful:
        return "", 0.0
    # Trace/pass tokens and uncommon technical words are the best naming clues.
    chosen = useful[:6]
    phrase = clean_ident("_".join(chosen), 52).lower()
    score = 0.42
    if len(useful) >= 2:
        score += 0.10
    if len(raw) >= 12:
        score += 0.06
    if any(ch.isupper() for ch in raw) and any(ch.islower() for ch in raw):
        score += 0.03
    if re.search(r"DFLOW|ALLOC|COALESCE|SPILL|SCHED|PEEP|OPTIM|PARSE|DWARF|ELF|OPCODE|RELOC", raw, re.I):
        score += 0.12
    if raw.count("%") >= 3:
        score -= 0.06
    return phrase, max(0.0, min(score, 0.78))


def decomp_signals(text: str) -> tuple[list[str], Counter]:
    signals: list[str] = []
    roles = role_hits(text)
    cases = len(re.findall(r"\bcase\s+", text))
    calls = len(re.findall(r"\b(?:FUN_[0-9A-Fa-f]+|[A-Za-z_][A-Za-z0-9_]+)\s*\(", text))
    loops = len(re.findall(r"\b(?:for|while)\s*\(", text))
    if cases >= 8:
        signals.append(f"switch_dispatcher:{cases}_cases")
    elif cases >= 3:
        signals.append(f"switch:{cases}_cases")
    if loops >= 2:
        signals.append(f"iterative:{loops}_loops")
    if calls == 1 and len(text) < 900 and re.search(r"return\s+FUN_[0-9A-Fa-f]+\s*\(", text):
        signals.append("thin_return_wrapper")
    if len(text) < 650 and re.search(r"FUN_[0-9A-Fa-f]+\s*\([^;]*\);\s*\}", text, re.S):
        signals.append("thin_call_wrapper")
    if len(re.findall(r"\bDAT_[0-9A-Fa-f]+\s*=", text)) >= 4:
        signals.append("global_state_initializer")
    return signals, roles


def confidence_band(score: float) -> str:
    if score >= 0.82:
        return "high"
    if score >= 0.65:
        return "medium"
    return "speculative"


def combine_conf(signals: list[tuple[str, float]], conflict=False) -> float:
    if not signals:
        return 0.0
    vals = sorted((v for _, v in signals), reverse=True)
    score = vals[0]
    if len(vals) >= 2:
        score += 0.06
    if len(vals) >= 3:
        score += 0.04
    if len(vals) >= 4:
        score += 0.025
    if conflict:
        score -= 0.10
    return round(max(0.0, min(score, 0.96)), 3)


def main() -> int:
    HERE.mkdir(parents=True, exist_ok=True)
    functions = {r["entry"].lower(): r for r in read_table(FUNCTIONS)}
    funset = set(functions)

    # Direct source-file anchors.
    source_rows = read_table(SOURCE_MAP)
    sources: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for r in source_rows:
        a = r["function_entry"].lower()
        if a in funset:
            sources[a].append((r["source_file"], float(r["confidence"])))
    direct_module: dict[str, tuple[str, float, str]] = {}
    for a, vals in sources.items():
        vals.sort(key=lambda x: x[1], reverse=True)
        path, conf = vals[0]
        direct_module[a] = (module_from_source(path), min(0.82, 0.66 + 0.16 * conf), path)

    # String xrefs, retaining every direct string for evidence and role voting.
    xref_rows = read_table(STRING_XREFS)
    strings: dict[str, list[str]] = defaultdict(list)
    string_records: dict[str, list[dict[str, str]]] = defaultdict(list)
    text_xref_count = Counter(r["string"] for r in xref_rows)
    for r in xref_rows:
        a = r["function_entry"].lower()
        if a in funset:
            strings[a].append(r["string"])
            string_records[a].append({
                "string_va": norm_va(r["string_addr"]),
                "text": r["string"],
                "xref_from": norm_va(r["xref_from"]),
            })

    # Registry categories and vtable membership/slot numbers.
    class_category = {r["name"]: r["category"] for r in read_table(REGISTRY)}
    vmembers: dict[str, list[dict]] = defaultdict(list)
    for r in read_table(VTABLES):
        cls = r["name"]
        for slot_index, m in enumerate(ADDR.finditer(r["slots"])):
            a = m.group(1).lower()
            if a in funset:
                vmembers[a].append({
                    "class": cls,
                    "category": class_category.get(cls, "other"),
                    "slot": slot_index,
                    "record_va": r["record_va"],
                    "vptr_va": r["vptr_va"],
                })

    # Existing semantic names, plus the curated backend map as high-value anchors.
    current_semantic: dict[str, str] = {
        a: f["name"] for a, f in functions.items() if not DEFAULT_NAME.fullmatch(f["name"])
    }
    semantic: dict[str, str] = {
        a: f["name"]
        for a, f in functions.items()
        if f["source"] == "USER_DEFINED" and not DEFAULT_NAME.fullmatch(f["name"])
    }
    backend_roles: dict[str, tuple[str, str, str]] = {}
    if BACKEND_FUNCTIONS.exists():
        for r in read_table(BACKEND_FUNCTIONS, delimiter=","):
            a = r["entry"].removeprefix("0x").lower()
            backend_roles[a] = (r["name"], r["role"], r["confidence"])
            semantic.setdefault(a, r["name"])

    options_by_semantic_name: dict[str, list[dict[str, str]]] = defaultdict(list)
    if OPTION_GLOBALS.exists():
        for r in read_table(OPTION_GLOBALS, delimiter=","):
            for fn in filter(None, r["functions"].split(";")):
                options_by_semantic_name[fn].append({
                    "option_id": r["option_id"],
                    "option_name": r["option_name"],
                    "address": norm_va(r["address"]),
                    "observed_effect": r["observed_effect"],
                    "confidence": r["confidence"],
                })

    # Direct callgraph neighborhoods.
    graph: dict[str, set[str]] = defaultdict(set)
    outgoing: dict[str, set[str]] = defaultdict(set)
    incoming: dict[str, set[str]] = defaultdict(set)
    for r in read_table(CALLGRAPH):
        a, b = r["caller_addr"].lower(), r["callee_addr"].lower()
        if a in funset and b in funset:
            graph[a].add(b)
            graph[b].add(a)
            outgoing[a].add(b)
            incoming[b].add(a)

    # Propagate source modules through two graph rounds.  Every inferred label
    # records its supporting neighbors and loses confidence each hop.
    module_labels: dict[str, tuple[str, float, str, list[str]]] = {
        a: (mod, conf, "direct_source", [path]) for a, (mod, conf, path) in direct_module.items()
    }
    for round_no in (1, 2):
        additions = {}
        for a in sorted(funset - module_labels.keys(), key=lambda x: int(x, 16)):
            votes: dict[str, list[tuple[str, float]]] = defaultdict(list)
            for n in sorted(graph.get(a, ()), key=lambda x: int(x, 16)):
                if n in module_labels:
                    mod, conf, _, _ = module_labels[n]
                    votes[mod].append((n, conf))
            if not votes:
                continue
            ranked = sorted(
                votes.items(),
                key=lambda kv: (-sum(c for _, c in kv[1]), -len(kv[1]), kv[0]),
            )
            mod, supporters = ranked[0]
            supporters = sorted(supporters, key=lambda x: int(x[0], 16))
            total_support = sum(len(v) for v in votes.values())
            ratio = len(supporters) / total_support
            if len(supporters) < 2 or ratio < (0.62 if round_no == 1 else 0.70):
                continue
            avg = sum(c for _, c in supporters) / len(supporters)
            conf = min(0.69 if round_no == 1 else 0.58, avg - (0.12 if round_no == 1 else 0.20) + min(0.08, 0.02 * len(supporters)))
            if conf < 0.45:
                continue
            additions[a] = (mod, conf, f"callgraph_round_{round_no}", [n for n, _ in supporters[:8]])
        module_labels.update(additions)

    # Address-local source bracketing is weaker than graph propagation but broad.
    anchors = sorted(direct_module, key=lambda x: int(x, 16))
    anchor_ints = [int(a, 16) for a in anchors]
    import bisect

    def address_module(a: str):
        x = int(a, 16)
        i = bisect.bisect_left(anchor_ints, x)
        if i == 0 or i == len(anchors):
            return None
        left, right = anchors[i - 1], anchors[i]
        lm, _, lp = direct_module[left]
        rm, _, rp = direct_module[right]
        if lm != rm:
            return None
        span = int(right, 16) - int(left, 16)
        if span > 0x18000:
            return None
        conf = max(0.43, 0.58 - span / 0x100000)
        return lm, round(conf, 3), "address_bracket", [left, right, lp, rp]

    # Decompiled text keyed by address.
    decomp: dict[str, str] = {}
    decomp_paths: dict[str, Path] = {}
    all_decomp_paths: list[Path] = []
    for pattern in DECOMP_GLOBS:
        all_decomp_paths.extend(Path(p) for p in sorted(glob.glob(str(ROOT / pattern), recursive=True)))
    # Glob priority above is semantic: newer wave exports first, broad legacy
    # exports second, specialized exports only as fallback. Deduplicate paths.
    seen_paths = set()
    all_decomp_paths = [p for p in all_decomp_paths if not (str(p) in seen_paths or seen_paths.add(str(p)))]
    for p in all_decomp_paths:
        m = DECOMP_ADDR.match(p.name)
        if m and m.group(1).lower() in funset and m.group(1).lower() not in decomp:
            decomp[m.group(1).lower()] = p.read_text(encoding="utf-8", errors="replace")
            decomp_paths[m.group(1).lower()] = p

    # Facts-only function records. Upstream source associations are explicitly
    # marked as upstream hypotheses rather than being mixed into observations.
    observed_rows = []
    for a in sorted(funset, key=lambda x: int(x, 16)):
        f = functions[a]
        observed_rows.append({
            "record_type": "observed_function",
            "va": norm_va(a),
            "raw_name": f["name"],
            "name_source": f["source"],
            "body_min": norm_va(f["body_min"]),
            "body_max": norm_va(f["body_max"]),
            "body_size": int(f["body_size"]),
            "caller_refs_reported": int(f["caller_refs"]),
            "callee_count_reported": int(f["callee_count"]),
            "thunk": f["thunk"].lower() == "true",
            "direct_callers": [norm_va(x) for x in sorted(incoming.get(a, ()), key=lambda x: int(x, 16))],
            "direct_callees": [norm_va(x) for x in sorted(outgoing.get(a, ()), key=lambda x: int(x, 16))],
            "string_xrefs": string_records.get(a, []),
            "vtable_memberships": classes if (classes := vmembers.get(a, [])) else [],
            "decompiled_path": str(decomp_paths[a].relative_to(ROOT)) if a in decomp_paths else None,
            "decompiled_bytes": len(decomp[a]) if a in decomp else 0,
            "upstream_source_associations": [
                {"source_file": p, "confidence": c, "provenance": "analysis/prime/source_file_function_map.tsv"}
                for p, c in sources.get(a, [])
            ],
            "provenance": [
                "analysis/ghidra/out/inventory/functions.tsv",
                "analysis/full_decomp/callgraph.tsv",
                "analysis/ghidra/out/all_string_xrefs.tsv",
                "analysis/worker3_static_map/ghs_vtables.tsv",
                *( [str(decomp_paths[a].relative_to(ROOT))] if a in decomp_paths else [] ),
            ],
        })
    with (HERE / "observations.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for row in observed_rows:
            f.write(json.dumps(row, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")

    proposals = []
    for a in sorted(funset, key=lambda x: int(x, 16)):
        f = functions[a]
        if not DEFAULT_NAME.fullmatch(f["name"]):
            continue

        evidence: dict[str, object] = {}
        evidence_refs: list[str] = []
        conf_signals: list[tuple[str, float]] = []
        role_votes = Counter()
        module = ""
        module_conf = 0.0
        module_kind = ""

        if a in module_labels:
            module, module_conf, module_kind, support = module_labels[a]
            evidence["module"] = {"name": module, "kind": module_kind, "support": support}
            conf_signals.append((module_kind, module_conf))
            if module_kind == "direct_source":
                evidence_refs.extend(f"source_map:{s}" for s in support)
            elif module_kind.startswith("callgraph_round_"):
                evidence_refs.extend(f"callgraph:{norm_va(a)}<->{norm_va(s)}" for s in support)
        else:
            addr_mod = address_module(a)
            if addr_mod:
                module, module_conf, module_kind, support = addr_mod
                evidence["module"] = {"name": module, "kind": module_kind, "support": support}
                conf_signals.append((module_kind, module_conf))
                evidence_refs.extend(
                    f"source_bracket:{norm_va(s)}" if re.fullmatch(r"[0-9a-fA-F]{8}", s) else f"source_map:{s}"
                    for s in support
                )

        classes = vmembers.get(a, [])
        unique_classes = sorted({v["class"] for v in classes})
        if classes:
            evidence["vtables"] = classes[:16]
            vconf = 0.84 if len(unique_classes) == 1 else 0.68
            conf_signals.append(("vtable", vconf))
            role_votes.update({"virtual_method": 2})
            evidence_refs.extend(
                f"vtable:{v['record_va']}:slot:{v['slot']}:{v['class']}" for v in classes[:16]
            )

        direct_strings = strings.get(a, [])
        best_phrase = ""
        best_phrase_score = 0.0
        best_string = ""
        string_roles = Counter()
        if direct_strings:
            ranked_strings = []
            for s in direct_strings:
                phrase, score = phrase_from_string(s)
                # Penalize strings shared by many functions; reward unique traces.
                refs = text_xref_count[s]
                if refs > 12:
                    score -= 0.16
                elif refs > 4:
                    score -= 0.08
                elif refs == 1:
                    score += 0.05
                ranked_strings.append((score, s, phrase, refs))
                string_roles.update(role_hits(s))
            ranked_strings.sort(reverse=True)
            score, best_string, best_phrase, _ = ranked_strings[0]
            best_phrase_score = max(0.0, min(score, 0.83))
            evidence["strings"] = [
                {"text": s, "phrase": p, "quality": round(sc, 3), "global_xrefs": refs}
                for sc, s, p, refs in ranked_strings[:8]
            ]
            if best_phrase and best_phrase_score >= 0.48:
                conf_signals.append(("direct_string", best_phrase_score))
            role_votes.update(string_roles)
            evidence_refs.extend(
                f"string_xref:{r['string_va']}@{r['xref_from']}" for r in string_records.get(a, [])[:16]
            )

        body_signals = []
        if a in decomp:
            body_signals, body_roles = decomp_signals(decomp[a])
            role_votes.update(body_roles)
            if body_signals or body_roles:
                evidence["decompiled_body"] = {
                    "signals": body_signals,
                    "role_hits": dict(body_roles.most_common(8)),
                    "bytes": len(decomp[a]),
                }
                conf_signals.append(("decompiled_body", 0.52 if body_roles else 0.46))
                evidence_refs.append(f"decompiled:{decomp_paths[a].relative_to(ROOT)}")

        named_neighbors = []
        for n in sorted(graph.get(a, ()), key=lambda x: int(x, 16)):
            if n in semantic:
                direction = "callee" if n in outgoing.get(a, ()) else "caller"
                named_neighbors.append({"address": n, "name": semantic[n], "direction": direction})
                role_votes.update(role_hits(semantic[n].replace("_", " ")))
        if named_neighbors:
            evidence["semantic_neighbors"] = named_neighbors[:12]
            nconf = min(0.62, 0.44 + 0.03 * len(named_neighbors))
            conf_signals.append(("semantic_neighbor", nconf))
            for n in named_neighbors[:12]:
                if n["direction"] == "callee":
                    evidence_refs.append(f"callgraph:{norm_va(a)}->{norm_va(n['address'])}")
                else:
                    evidence_refs.append(f"callgraph:{norm_va(n['address'])}->{norm_va(a)}")

        if a in backend_roles:
            bn, br, bc = backend_roles[a]
            evidence["backend_map"] = {"name": bn, "role": br, "confidence": bc}
            conf_signals.append(("backend_map", 0.92 if bc == "high" else 0.82))
            role_votes.update(role_hits(br))
            evidence_refs.append(f"backend_map:function_map.csv:{norm_va(a)}")

        if not conf_signals:
            continue

        role = role_votes.most_common(1)[0][0] if role_votes else "helper"
        role_strength = role_votes.most_common(1)[0][1] if role_votes else 0
        if role_strength:
            evidence["role_votes"] = dict(role_votes.most_common(10))

        # The name encodes the strongest concrete structural clue first.  An
        # address suffix keeps proposals unique and makes blind application unnecessary.
        suffix = a[-6:]
        proposal_kind = ""
        if a in backend_roles:
            bn, _, _ = backend_roles[a]
            proposed = bn
            proposal_kind = "curated_backend_map"
        elif len(unique_classes) == 1:
            cls = clean_ident(unique_classes[0], 42)
            slots = sorted({v["slot"] for v in classes})
            slot_text = f"vslot_{slots[0]:03d}" if len(slots) == 1 else f"vslots_{slots[0]:03d}_{slots[-1]:03d}"
            extra = "" if role == "virtual_method" else "_" + clean_ident(role, 28)
            proposed = f"{cls}__{slot_text}{extra}_{suffix}"
            proposal_kind = "class_vmethod"
        elif best_phrase and best_phrase_score >= 0.62:
            prefix = module if module else clean_ident(role, 32)
            proposed = f"{prefix}__{best_phrase}_{suffix}"
            proposal_kind = "string_semantic"
        elif module:
            proposed = f"{module}__{clean_ident(role, 32)}_{suffix}"
            proposal_kind = "module_role"
        elif role != "helper":
            proposed = f"{clean_ident(role, 36)}__helper_{suffix}"
            proposal_kind = "role_only"
        elif named_neighbors:
            anchor = clean_ident(named_neighbors[0]["name"], 42)
            proposed = f"{anchor}__neighbor_{suffix}"
            proposal_kind = "named_neighbor"
        else:
            proposed = f"semantic_helper_{suffix}"
            proposal_kind = "weak_evidence"

        conflict = False
        if len(unique_classes) > 1:
            conflict = True
        if module and a in direct_module and direct_module[a][0] != module:
            conflict = True
        score = combine_conf(conf_signals, conflict=conflict)

        role_desc_parts = []
        if len(unique_classes) == 1:
            role_desc_parts.append(f"virtual method of {unique_classes[0]}")
        elif len(unique_classes) > 1:
            role_desc_parts.append("shared virtual method")
        if role != "helper" and role != "virtual_method":
            role_desc_parts.append(role.replace("_", " "))
        if module:
            role_desc_parts.append(f"module {module}")
        if body_signals:
            role_desc_parts.append(", ".join(body_signals[:2]))
        if best_string:
            role_desc_parts.append(f"string clue: {best_string[:120]}")
        role_desc = "; ".join(role_desc_parts) or "semantic neighborhood helper"

        related_options = options_by_semantic_name.get(backend_roles[a][0], []) if a in backend_roles else []
        observed_refs = [
            ref for ref in dict.fromkeys(evidence_refs)
            if ref.startswith(("callgraph:", "vtable:", "string_xref:", "decompiled:"))
        ]
        upstream_refs = [
            ref for ref in dict.fromkeys(evidence_refs)
            if ref.startswith(("source_map:", "source_bracket:", "backend_map:"))
        ]
        provenance_sources = set()
        for kind, _ in conf_signals:
            if kind in {"direct_source", "address_bracket"}:
                provenance_sources.add("analysis/prime/source_file_function_map.tsv")
            if kind.startswith("callgraph_round_") or kind == "semantic_neighbor":
                provenance_sources.add("analysis/full_decomp/callgraph.tsv")
            if kind == "vtable":
                provenance_sources.add("analysis/worker3_static_map/ghs_vtables.tsv")
                provenance_sources.add("analysis/worker3_static_map/ghs_registry.tsv")
            if kind == "direct_string":
                provenance_sources.add("analysis/ghidra/out/all_string_xrefs.tsv")
            if kind == "decompiled_body" and a in decomp_paths:
                provenance_sources.add(str(decomp_paths[a].relative_to(ROOT)))
            if kind == "backend_map":
                provenance_sources.add("analysis/backend_map/function_map.csv")
        if related_options:
            provenance_sources.add("analysis/backend_map/option_globals.csv")

        proposals.append({
            "record_type": "naming_hypothesis",
            "va": norm_va(a),
            "raw_name": f["name"],
            "name_source": f["source"],
            "proposed_name": clean_ident(proposed, 110),
            "role_hypothesis": role_desc,
            "confidence": score,
            "confidence_band": confidence_band(score),
            "proposal_kind": proposal_kind,
            "module_hypothesis": module,
            "module_evidence_kind": module_kind,
            "class_names_observed": ";".join(unique_classes),
            "vtable_slots_observed": ";".join(f"{v['class']}:{v['slot']}" for v in classes[:20]),
            "source_associations_upstream": ";".join(p for p, _ in sources.get(a, [])[:8]),
            "best_string": best_string[:300],
            "best_string_quality": round(best_phrase_score, 3),
            "direct_callers": ";".join(norm_va(x) for x in sorted(incoming.get(a, ()), key=lambda x: int(x, 16))),
            "direct_callees": ";".join(norm_va(x) for x in sorted(outgoing.get(a, ()), key=lambda x: int(x, 16))),
            "named_neighbors": ";".join(f"{n['direction']}:{n['name']}@{norm_va(n['address'])}" for n in named_neighbors[:12]),
            "related_options": json.dumps(related_options, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            "decompiled": a in decomp,
            "evidence_count": len(conf_signals),
            "evidence_kinds": ";".join(name for name, _ in conf_signals),
            "evidence_refs": ";".join(dict.fromkeys(evidence_refs)),
            "observed_evidence_refs": ";".join(observed_refs),
            "upstream_hypothesis_refs": ";".join(upstream_refs),
            "provenance": "analysis/auto_names/build_auto_names.py",
            "provenance_sources": ";".join(sorted(provenance_sources)),
            "evidence_json": json.dumps(evidence, ensure_ascii=True, separators=(",", ":")),
        })

    proposals.sort(key=lambda r: (-r["confidence"], int(r["va"], 16)))
    fields = list(proposals[0].keys()) if proposals else []
    with (HERE / "proposals.tsv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, delimiter="\t")
        w.writeheader()
        w.writerows(proposals)
    with (HERE / "proposals.jsonl").open("w", encoding="utf-8", newline="\n") as f:
        for row in proposals:
            obj = dict(row)
            obj["direct_callers"] = [x for x in row["direct_callers"].split(";") if x]
            obj["direct_callees"] = [x for x in row["direct_callees"].split(";") if x]
            obj["evidence_kinds"] = [x for x in row["evidence_kinds"].split(";") if x]
            obj["evidence_refs"] = [x for x in row["evidence_refs"].split(";") if x]
            obj["observed_evidence_refs"] = [x for x in row["observed_evidence_refs"].split(";") if x]
            obj["upstream_hypothesis_refs"] = [x for x in row["upstream_hypothesis_refs"].split(";") if x]
            obj["provenance_sources"] = [x for x in row["provenance_sources"].split(";") if x]
            obj["related_options"] = json.loads(row["related_options"])
            obj["evidence"] = json.loads(row["evidence_json"])
            del obj["evidence_json"]
            f.write(json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")

    bands = Counter(r["confidence_band"] for r in proposals)
    kinds = Counter(r["proposal_kind"] for r in proposals)
    evidence_types = Counter()
    roles = Counter()
    modules = Counter()
    for r in proposals:
        evidence_types.update(r["evidence_kinds"].split(";") if r["evidence_kinds"] else [])
        if r["module_hypothesis"]:
            modules[r["module_hypothesis"]] += 1
        role_key = r["proposed_name"].split("__", 1)[0]
        roles[role_key] += 1

    stats = {
        "functions_total": len(functions),
        "unnamed_functions": sum(bool(DEFAULT_NAME.fullmatch(f["name"])) for f in functions.values()),
        "proposal_count": len(proposals),
        "bands": dict(bands),
        "proposal_kinds": dict(kinds),
        "evidence_types": dict(evidence_types),
        "top_modules": modules.most_common(30),
        "decompiled_inputs": len(decomp),
        "direct_source_anchors": len(direct_module),
        "direct_string_functions": len(strings),
        "vtable_member_functions": len(vmembers),
        "current_semantic_labels": len(current_semantic),
        "semantic_anchor_names": len(semantic),
    }
    (HERE / "summary.json").write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")

    summary_md = [
        "# auto_names summary",
        "",
        f"- schema_version: 1",
        f"- functions_total: {stats['functions_total']}",
        f"- unnamed_functions: {stats['unnamed_functions']}",
        f"- proposal_count: {stats['proposal_count']}",
        f"- high: {bands.get('high', 0)}",
        f"- medium: {bands.get('medium', 0)}",
        f"- speculative: {bands.get('speculative', 0)}",
        f"- observed_function_rows: {len(observed_rows)}",
        "",
        "## proposal_kind_counts",
        "",
        "```json",
        json.dumps(dict(sorted(kinds.items())), indent=2),
        "```",
        "",
        "## evidence_kind_counts",
        "",
        "```json",
        json.dumps(dict(sorted(evidence_types.items())), indent=2),
        "```",
        "",
        "## resume",
        "",
        "`python3 analysis/auto_names/build_auto_names.py`",
        "",
        "Facts and hypotheses are separated: `observations.jsonl` contains function/xref/vtable/callgraph observations; `proposals.tsv` and `proposals.jsonl` contain inferred semantic names/roles.",
    ]
    (HERE / "summary.md").write_text("\n".join(summary_md) + "\n", encoding="utf-8")

    schema = {
        "schema_version": 1,
        "va_format": "0x + 8 lowercase hexadecimal digits",
        "record_types": {
            "observed_function": "facts/current-state exported or structurally recovered from local analysis artifacts",
            "naming_hypothesis": "inferred semantic name/role; never auto-applied to Ghidra",
        },
        "confidence": {"range": [0.0, 1.0], "high_min": 0.82, "medium_min": 0.65},
        "separation": {
            "observations": "analysis/auto_names/observations.jsonl",
            "hypotheses_tsv": "analysis/auto_names/proposals.tsv",
            "hypotheses_jsonl": "analysis/auto_names/proposals.jsonl",
            "observed_evidence_refs_field": "observed_evidence_refs",
            "upstream_hypothesis_refs_field": "upstream_hypothesis_refs",
        },
        "determinism": "rows sort by descending confidence then ascending VA; arrays/sets use deterministic VA/name ordering",
    }
    (HERE / "schema.json").write_text(json.dumps(schema, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    inputs = [FUNCTIONS, SOURCE_MAP, STRING_XREFS, CALLGRAPH, VTABLES, REGISTRY, BACKEND_FUNCTIONS, OPTION_GLOBALS]
    checkpoint = {
        "schema_version": 1,
        "generator": "analysis/auto_names/build_auto_names.py",
        "generator_sha256": sha256_file(Path(__file__)),
        "resume_command": "python3 analysis/auto_names/build_auto_names.py",
        "inputs": [
            {"path": str(p.relative_to(ROOT)), "sha256": sha256_file(p), "bytes": p.stat().st_size}
            for p in inputs if p.exists()
        ],
        "decompiled_input": {
            "globs": DECOMP_GLOBS,
            "file_count": len(all_decomp_paths),
            "aggregate_sha256": sha256_decomp(all_decomp_paths),
        },
        "outputs": [
            "analysis/auto_names/observations.jsonl",
            "analysis/auto_names/proposals.tsv",
            "analysis/auto_names/proposals.jsonl",
            "analysis/auto_names/schema.json",
            "analysis/auto_names/summary.json",
            "analysis/auto_names/summary.md",
        ],
        "counts": stats,
    }
    checkpoint["output_digests"] = [
        {"path": str(p.relative_to(ROOT)), "sha256": sha256_file(p), "bytes": p.stat().st_size}
        for p in [
            HERE / "observations.jsonl",
            HERE / "proposals.tsv",
            HERE / "proposals.jsonl",
            HERE / "schema.json",
            HERE / "summary.json",
            HERE / "summary.md",
        ]
    ]
    (HERE / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
