#!/usr/bin/env python3
"""Build the compact ecomppc backend-control map from existing local analysis.

This script intentionally emits only addresses, names, control relationships, and
evidence pointers. It does not copy executable bytes or decompiler output.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
OPTION_BASE = 0x00C4064E


FUNCTIONS = [
    # entry, end, size, name, role, confidence, evidence
    (0x006AE504, 0x006AE5C8, 197, "codegen", "top-level independent backend driver", "high", "Ghidra call graph; codegen timing string"),
    (0x006AD8D8, 0x006ADF1B, 1604, "independent_optimize", "machine-independent optimization before backend lowering", "high", "calls dooptimize at 0x006adb2b"),
    (0x00545735, 0x0054619F, 2667, "dooptimize", "main optimizer pass orchestrator", "high", "embedded dooptimize string and optimizer-pass callees"),
    (0x006A0B1D, 0x006A0E05, 745, "makeproc", "build machine procedure / backend procedure state; stage tag 1", "high", "makeproc timing string; stage write"),
    (0x006A535B, 0x006A55D9, 639, "allocation_prepare_driver", "pre-register-allocation preparation and path selection", "medium-high", "calls 0x006a527d; graph_allocate chooses retick path"),
    (0x006A527D, 0x006A535A, 222, "prealloc_phase2", "pre-allocation cleanup/dataflow/peephole/scheduling wrapper; stage tag 2", "medium-high", "stage write; predataflow and pre_alloc_scheduling calls"),
    (0x006A50BB, 0x006A51DC, 290, "prealloc_vn_dataflow", "temporary stage 4 VN/dataflow then stage 5 post-dataflow work", "high", "calls dflow_vn_forward_apply; writes stage 4 then 5"),
    (0x006A51DD, 0x006A527C, 160, "pre_alloc_scheduling", "optional early scheduling; stage tag 3", "high", "pre-alloc scheduling timing string"),
    (0x0066FAD9, 0x0066FDEE, 790, "schedule_pass_1", "classic pipeline/gap scheduler", "high", "Before/After Scheduling strings; showpipe diagnostics"),
    (0x00739E6A, 0x0073A362, 1273, "schedule_pass_2", "PPC750/PPC7450 secondary resource scheduler", "high", "explicit ppc750/ppc7450 gates and list-scheduler knobs"),
    (0x0073A363, 0x0073A67C, 794, "schedule_pass_3", "list scheduler selected by listscheduler", "high", "listscheduler dispatch; list-scheduler diagnostics"),
    (0x006ADF1C, 0x006AE05B, 320, "allocate_registers", "register-allocation stage driver; stage tag 6", "high", "register_allocation_core/fixup/dataflow/branch calls"),
    (0x0069BF55, 0x0069C296, 834, "register_allocation_core", "register allocator dispatcher", "high", "register allocation timing string; graph_allocate branch"),
    (0x0069BA54, 0x0069BF54, 1281, "allocator_local_path", "non-primary/default allocator path; can invoke local reduce/coalesce/spill machinery", "medium", "selected by register_allocation_core when graph_allocate is off or procedure is non-primary"),
    (0x0071D3EF, 0x0071DA13, 1573, "graph_allocator_primary_path", "graph_allocate primary-procedure allocator candidate", "medium-high", "selected only when graph_allocate is set for primary procedure; allocator-loop structure"),
    (0x0074D02A, 0x0074D2DF, 694, "allocregs_local_driver", "two-attempt allocation driver: temps first, then permanent registers", "high", "ALLOC START only temps / ALLOC SWITCH with perms strings"),
    (0x0074C881, 0x0074CDE4, 1380, "coalesce_spill_retry_loop", "iterative reduce/coalesce/spill loop with 200-iteration cap", "high", "calls coalesce_stage then spill_stage; MAX VAR SPILLS/REORDER strings"),
    (0x0074C01C, 0x0074C4C2, 1191, "coalesce_stage", "register-variable coalescing stage", "high", "COALESCE stage string"),
    (0x0074C6E1, 0x0074C880, 416, "spill_stage", "register spill selection/rewrite stage", "high", "SPILL stage string"),
    (0x006AC8EB, 0x006ACA14, 298, "fixup_driver", "post-allocation fixup; stage tag 7; may rerun allocation", "high", "fixuptwice condition and register_allocation_core call"),
    (0x006ACA15, 0x006ACE62, 1102, "backend_dataflow_peephole", "backend VN/dataflow and peephole stages; stage tags 8/9", "high", "dataflow/ipeep option gates and stage writes"),
    (0x0076EF82, 0x0076FD2D, 3500, "dflow_vn_forward_apply", "forward dataflow/value-numbering engine", "high", "DFLOW/VN strings and backend_dataflow_peephole call"),
    (0x006D183D, 0x006D25FD, 3521, "peephole_pass_2", "late backend peephole engine", "high", "peephole strings and repeated backend calls"),
    (0x006ACE63, 0x006ACFA4, 322, "branch_optimize_driver", "branch/lifetime setup; stage tags 9 then 10", "high", "dumpbeforebranches/rotate_blocks/lifetime gates"),
    (0x006747DE, 0x0067538D, 2992, "branches_and_post_alloc", "branch cleanup, expand-code, late scheduling, nop removal", "high", "post-alloc scheduling and branch debug strings"),
    (0x006AE05C, 0x006AE38A, 815, "codewrite", "final target emission / debug-output stage; stage tag 11", "high", "stage write and target vtable emission callback"),
]


# id, name, functions, observed control effect, confidence
OPTIONS = [
    (8, "dataflow", "backend_dataflow_peephole", "master enable for backend VN/dataflow passes", "high"),
    (9, "nopeep", "backend_dataflow_peephole", "disables normal peephole path", "high"),
    (76, "nobranches", "branches_and_post_alloc", "skips main branch merge/removal loop when set", "high"),
    (179, "fixuptwice", "fixup_driver", "if fixup marks changes, reruns register_allocation_core and fixup", "high"),
    (267, "SS_schedule", "branches_and_post_alloc", "after schedule_pass_1, additionally runs schedule_pass_2", "high"),
    (301, "merge_paired_comparisons", "branches_and_post_alloc", "enables paired-comparison merge cleanup", "high"),
    (307, "noschedule", "schedule_pass_1;schedule_pass_2;schedule_pass_3", "blocks scheduler bodies", "high"),
    (310, "showpipe", "schedule_pass_1;schedule_pass_2;schedule_pass_3", "enables scheduler diagnostics", "high"),
    (383, "preenterexit", "fixup_driver;branch_optimize_driver", "runs enter/exit processing before fixup; suppresses branch driver's fallback enter/exit path", "high"),
    (396, "dump_after_remove_stupidbranches", "branches_and_post_alloc", "dumps code after branch shortening/removal pass", "high"),
    (701, "ls_write_after_read_grouping", "schedule_pass_2;schedule_pass_3", "list-scheduler dependency-grouping knob", "high"),
    (799, "noshortenbranches", "branches_and_post_alloc", "skips remove/shorten-stupid-branches pass", "high"),
    (802, "smallandslow", "branches_and_post_alloc", "suppresses branchtaken_is_better rewrite", "high"),
    (1059, "ipeep2", "backend_dataflow_peephole", "enables indirect peephole-pass-2 path", "high"),
    (1060, "noindpeep1", "backend_dataflow_peephole", "disables independent peephole-pass-1 path", "high"),
    (1062, "ls_correct_issue_false_depend", "schedule_pass_2;schedule_pass_3", "list-scheduler false-dependency correction knob", "high"),
    (1066, "ipeep2a", "backend_dataflow_peephole", "enables alternate peephole-pass-2 path", "high"),
    (1081, "predataflow", "prealloc_phase2", "invokes prealloc_vn_dataflow before early scheduling", "high"),
    (1089, "ls_issue_false_depend", "schedule_pass_2;schedule_pass_3", "list-scheduler issue false-dependency knob", "high"),
    (1112, "abortschedule", "schedule_pass_1", "changes scheduler retry/abort behavior", "medium-high"),
    (1139, "earlyschedule", "pre_alloc_scheduling", "enables pre-allocation scheduling", "high"),
    (1140, "ls_critlength_no_false_depend", "schedule_pass_2;schedule_pass_3", "list-scheduler critical-length knob", "high"),
    (1172, "showframesize", "allocate_registers", "prints/reports computed frame size", "high"),
    (1257, "prepeep", "prealloc_phase2;allocation_prepare_driver", "enables pre-allocation peephole work and forces full phase-2 preparation", "high"),
    (1304, "nolateschedule", "branches_and_post_alloc", "skips post-allocation scheduling entirely", "high"),
    (1343, "postfixuppreenterexit", "fixup_driver;branch_optimize_driver", "runs enter/exit processing after fixup; suppresses branch fallback path", "high"),
    (1466, "prunebeforepipe", "schedule_pass_1", "saves/restores/prunes scheduler input before pipeline scheduling", "medium-high"),
    (1579, "ppc750", "schedule_pass_2", "one of two CPU gates required for schedule_pass_2", "high"),
    (1599, "ls_better_sum_delay", "schedule_pass_2;schedule_pass_3", "list-scheduler delay-scoring knob", "high"),
    (1611, "preadsfix", "prealloc_phase2;allocation_prepare_driver", "runs pre-allocation address-fix helper", "high"),
    (1722, "convergedeadblocks", "branches_and_post_alloc", "chooses converging late-dead-block helper", "high"),
    (1735, "latedeadblocks", "branches_and_post_alloc", "enables late dead-block removal", "high"),
    (1799, "graph_alloc_bcl", "graph_allocator_primary_path", "enables graph-allocation behavior for smaller procedures", "medium-high"),
    (1851, "graph_allocate", "allocation_prepare_driver;register_allocation_core;allocator_local_path", "selects graph-aware preparation and primary-procedure allocator path", "high"),
    (1886, "ip2scanpastlocalbranch", "backend_dataflow_peephole", "changes peephole-pass-2 scanning across local branches", "medium-high"),
    (2009, "extend_lifetime", "branch_optimize_driver;graph_allocator_primary_path", "enables lifetime extension/debug path", "high"),
    (2133, "software_pipeline", "schedule_pass_1;schedule_pass_3", "runs software-pipeline preparation before scheduling", "high"),
    (2146, "branchtaken_is_better", "branches_and_post_alloc", "enables branch-taken preference rewrite when smallandslow is clear", "high"),
    (2175, "long_schedule", "schedule_pass_1", "expands scheduler search/window limit from 0x1f to 0x3f", "high"),
    (2314, "ppc7450", "schedule_pass_2", "one of two CPU gates required for schedule_pass_2", "high"),
    (2361, "showpipegroup", "schedule_pass_2;schedule_pass_3", "enables scheduler group diagnostics", "high"),
    (2414, "dumpbeforeallocate", "allocate_registers", "dumps code immediately before register allocation", "high"),
    (2529, "dhecht5", "coalesce_spill_retry_loop;allocregs_local_driver", "extra allocator bookkeeping/verification path", "medium"),
    (2623, "listscheduler", "pre_alloc_scheduling;branches_and_post_alloc", "selects schedule_pass_3 instead of schedule_pass_1", "high"),
    (2661, "passtime", "codegen;register_allocation_core;pre_alloc_scheduling;branches_and_post_alloc", "enables pass timing begin/end instrumentation", "high"),
    (2866, "better_succs_preds", "branches_and_post_alloc", "expected invariant for branch pass; false triggers assertion helper", "medium-high"),
    (2873, "late_code_motion", "backend_dataflow_peephole", "enables late code-motion helper in peephole stage", "high"),
    (2944, "allocregs_with_movebias", "allocator_local_path;coalesce_spill_retry_loop", "builds/uses move-bias list during reduce/coalesce allocation", "high"),
    (2950, "allocregs_reducegraph_conservative", "allocator_local_path", "enables reduce-graph allocator path in conservative mode", "high"),
    (2951, "allocregs_reducegraph_fully", "allocator_local_path;coalesce_spill_retry_loop", "enables full reduce-graph allocator path", "high"),
    (2967, "showallocregs", "coalesce_spill_retry_loop;allocregs_local_driver", "prints allocator/coalesce/spill diagnostics", "high"),
    (3112, "dumpbeforeschedule", "schedule_pass_1;schedule_pass_2;schedule_pass_3", "dumps code before scheduler", "high"),
    (3113, "dumpafterschedule", "schedule_pass_1;schedule_pass_2;schedule_pass_3", "dumps code after scheduler", "high"),
    (3160, "allocregs_combine_fastslowregs", "allocator_local_path", "changes how fast/slow register classes are combined before local allocation", "medium-high"),
    (3207, "dhecht8", "allocator_local_path;coalesce_spill_retry_loop", "bypasses/changes coalesce-spill decisions in local allocator", "medium"),
    (3243, "better_graph_alloc_coalesce", "graph_allocator_primary_path", "enables extra graph-allocator coalescing bookkeeping", "medium-high"),
    (3354, "dataflow_postpeep2", "backend_dataflow_peephole", "enables second VN/dataflow run after peephole-2", "high"),
    (3476, "vn_nocopyprop", "prealloc_vn_dataflow", "temporarily forced when vn_no_pre_copyprop is also clear; controls prealloc VN copy propagation", "high"),
    (3714, "split_64bit_variables", "allocate_registers", "runs 64-bit variable split before allocation on 32-bit target", "high"),
    (3925, "vn_no_pre_copyprop", "prealloc_vn_dataflow", "causes vn_nocopyprop to be forced for prealloc VN pass", "high"),
    (3938, "rotate_blocks", "branch_optimize_driver", "runs block-rotation helper before branch pass", "high"),
    (4562, "remove_all_self_moves", "backend_dataflow_peephole", "removes remaining self-moves at end of backend peephole", "high"),
    (4568, "schedule_without_optimize", "schedule_pass_1;schedule_pass_2;schedule_pass_3", "permits scheduling even when normal optimization-state byte is clear", "high"),
    (4569, "peephole_without_optimize", "backend_dataflow_peephole", "permits peephole path without normal optimization state", "high"),
    (4572, "keep_variables_live", "allocator_local_path", "suppresses reduce-graph local allocator selection when set", "medium-high"),
    (4579, "loopoptimize_during_alloc", "register_allocation_core", "temporarily forces optimizer-state byte during register allocation", "high"),
    (4590, "dataflow_pass1", "backend_dataflow_peephole", "enables first backend VN/dataflow run", "high"),
    (4591, "dataflow_pass3", "backend_dataflow_peephole", "enables third backend VN/dataflow run", "high"),
]


PASS_ORDER = {
    "target": {
        "path": "ghs5.3.22/bin/ecomppc.exe",
        "sha256": "b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3",
        "image_base": "0x00400000",
        "entry_va": "0x00a938ff",
    },
    "option_byte_base": "0x00c4064e",
    "stage_tag_global": "0x00be2e20",
    "backend_order": [
        {"address": "0x006ad8d8", "name": "independent_optimize", "notes": "includes dooptimize"},
        {"address": "0x006a0b1d", "name": "makeproc", "stage": 1},
        {"address": "0x006a535b", "name": "allocation_prepare_driver", "notes": "contains optional phase2/prealloc dataflow/early scheduling/retick"},
        {"address": "0x006adf1c", "name": "allocate_registers", "stage": 6},
        {"address": "0x006ac8eb", "name": "fixup_driver", "stage": 7, "notes": "fixuptwice can rerun register_allocation_core"},
        {"address": "0x006aca15", "name": "backend_dataflow_peephole", "stages": [8, 9]},
        {"address": "0x006ace63", "name": "branch_optimize_driver", "stages": [9, 10]},
        {"address": "0x006ae05c", "name": "codewrite", "stage": 11},
    ],
    "prealloc_prepare": {
        "driver": "0x006a535b",
        "phase2": "0x006a527d",
        "phase2_stage": 2,
        "predataflow": {"gate": "predataflow", "address": "0x006a50bb", "temporary_stages": [4, 5]},
        "early_schedule": {"gate": "earlyschedule", "address": "0x006a51dd", "stage": 3, "listscheduler_false": "schedule_pass_1", "listscheduler_true": "schedule_pass_3"},
        "note": "stage tags are contextual markers, not a monotonic pass counter: the optional stage-4 VN subpass executes before the stage-3 early scheduler and restores the prior stage on return.",
    },
    "register_allocator": {
        "dispatcher": "0x0069bf55",
        "graph_allocate_false_or_nonprimary": "0x0069ba54",
        "graph_allocate_true_primary": "0x0071d3ef",
        "local_alloc_driver": "0x0074d02a",
        "coalesce_spill_loop": "0x0074c881",
        "coalesce_stage": "0x0074c01c",
        "spill_stage": "0x0074c6e1",
    },
    "postalloc_scheduler": {
        "owner": "0x006747de",
        "gate": "nolateschedule == 0",
        "listscheduler_false": ["schedule_pass_1", "schedule_pass_2 iff SS_schedule"],
        "listscheduler_true": ["schedule_pass_3"],
    },
}


def load_option_names() -> dict[int, set[str]]:
    names: dict[int, set[str]] = {}
    with (ROOT / "analysis/manual/internal_option_ids.tsv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            names.setdefault(int(row["id"]), set()).add(row["name"])
    return names


def validate_options(names: dict[int, set[str]]) -> None:
    failures: list[str] = []
    for option_id, name, *_ in OPTIONS:
        if name not in names.get(option_id, set()):
            failures.append(f"id {option_id}: expected {name!r}, table has {sorted(names.get(option_id, set()))}")
    if failures:
        raise SystemExit("option-table validation failed:\n" + "\n".join(failures))


def write_option_globals() -> None:
    with (OUT / "option_globals.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["address", "option_id", "option_name", "functions", "observed_effect", "confidence"])
        for option_id, name, functions, effect, confidence in OPTIONS:
            w.writerow([f"0x{OPTION_BASE + option_id:08x}", option_id, name, functions, effect, confidence])


def write_function_map() -> None:
    with (OUT / "function_map.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["entry", "end", "size", "name", "role", "confidence", "evidence"])
        for entry, end, size, name, role, confidence, evidence in FUNCTIONS:
            w.writerow([f"0x{entry:08x}", f"0x{end:08x}", size, name, role, confidence, evidence])


def main() -> None:
    names = load_option_names()
    validate_options(names)
    write_option_globals()
    write_function_map()
    (OUT / "pass_order.json").write_text(json.dumps(PASS_ORDER, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(OPTIONS)} option mappings, {len(FUNCTIONS)} functions, and pass_order.json")


if __name__ == "__main__":
    main()
