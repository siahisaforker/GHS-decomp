#!/usr/bin/env python3
"""Build structured static-analysis maps for GHS 5.3.22 ecomppc.exe.

The script reads the local proprietary executable and the repository's Ghidra
TSV exports, but writes only metadata, addresses, names, and short string clues.
It does not copy executable bytes into the generated artifacts.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import struct
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "ghs5.3.22/bin/ecomppc.exe"
INVENTORY = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
STRINGS = ROOT / "analysis/ghidra/out/all_string_xrefs.tsv"
OUT = Path(__file__).resolve().parent

EXPECTED_SHA256 = "b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3"
BACKEND_GLOBAL = 0x00BDB584
BACKEND_CTOR = 0x00424CEB
BACKEND_VTABLE = 0x00ABF65C
BACKEND_VTABLE_SPAN = 0x838


FUNCTION_ROLES = {
    0x00995FD0: ("probable_main_wrapper", "CRT passes argc/argv here; wrapper enters compiler bootstrap"),
    0x005B99A2: ("compiler_bootstrap_gen_init", "single caller from probable main wrapper; trace string is gen_init"),
    0x00545735: ("dooptimize", "high-level target-independent optimizer driver"),
    0x0051C208: ("propagateconstants", "constant propagation"),
    0x00500FBC: ("run_liveness_dataflow", "liveness dataflow"),
    0x0053EADE: ("loop_unroll", "loop unrolling"),
    0x0054C4A7: ("SIMD_vectorize", "SIMD vectorizer"),
    0x005522D5: ("find_loop_invariants", "loop invariant discovery"),
    0x005558F2: ("possible_induction_var", "induction-variable analysis"),
    0x00557560: ("check_possible_alias", "alias analysis helper"),
    0x00568597: ("object_motion", "object/code motion optimization"),
    0x00589E83: ("substitute_driver", "substitution/copy-style optimization driver"),
    0x005CB7E0: ("treepeep", "tree peephole optimizer"),
    0x0066B178: ("dflow_vn_forward", "forward value-numbering/dataflow"),
    0x0076EF82: ("dflow_vn_forward_apply", "backend forward VN/dataflow application"),
    0x006AD8D8: ("independent_optimize", "target-independent optimization phase around dooptimize"),
    0x006AE504: ("codegen", "top-level code generation driver"),
    0x006A0B1D: ("makeproc", "build/lower procedure before allocation"),
    0x006A51DD: ("pre_alloc_scheduling", "pre-allocation scheduling dispatcher"),
    0x006ADF1C: ("allocate_registers", "register-allocation wrapper plus post-allocation passes"),
    0x0069BF55: ("register_allocation_core", "core allocator; invokes target virtual hook +0x524"),
    0x0074C01C: ("coalesce_stage", "register coalescing stage"),
    0x0074C6E1: ("spill_stage", "register spill stage"),
    0x0071661C: ("spill_candidate", "spill candidate selection"),
    0x0071BC67: ("allocate_variable", "individual variable allocation"),
    0x006AC8EB: ("fixup_driver", "target fixup driver; virtual hooks +0x6c4/+0x474"),
    0x006ACA15: ("backend_dataflow_peephole", "backend VN/dataflow and peephole passes"),
    0x006D07E7: ("peephole_pass_1", "peephole pass 1"),
    0x006D183D: ("peephole_pass_2", "peephole pass 2"),
    0x006ACE63: ("branch_optimize_driver", "post-allocation branch optimization driver"),
    0x006747DE: ("branches_and_post_alloc", "branch cleanup, code expansion, post-allocation scheduling"),
    0x006EF6CB: ("optimize_tail_calls", "tail-call optimization"),
    0x0066FAD9: ("schedule_pass_1", "window/gap-filling scheduler"),
    0x00739E6A: ("schedule_pass_2", "selective/list rescheduling path"),
    0x0073A363: ("schedule_pass_3", "full list/resource-model scheduler path"),
    0x006AE05C: ("codewrite", "final target emission/output phase; virtual hook +0x5e4"),
    0x00424CEB: ("powerpc_backend_constructor", "allocates 0x251c-byte target object, installs vtable 0x00abf65c, stores global 0x00bdb584"),
}


VTABLE_ROLES = {
    0x394: "scheduler_relink_or_commit_hook",
    0x46C: "pre_branch_target_hook",
    0x474: "fixup_target_hook_noop_in_this_build",
    0x484: "post_expand_target_hook",
    0x524: "post_register_allocation_target_hook_noop_in_this_build",
    0x5E4: "final_codewrite_target_hook",
    0x67C: "branch_instruction_predicate_or_filter",
    0x6C4: "optional_fixup_target_hook_noop_in_this_build",
    0x834: "branch_merge_target_helper",
}


PPC_STRING_RE = re.compile(
    r"(?:\bppc\w*\b|powerpc|espresso|resource_scheduler|list_scheduler|"
    r"schedule|spill|coalesc|register allocation|codegen|peephole|"
    r"prologue|epilogue|tail call|binary_codegen)",
    re.IGNORECASE,
)


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8", errors="replace") as f:
        return list(csv.DictReader(f, delimiter="\t"))


def parse_pe(data: bytes) -> dict:
    if data[:2] != b"MZ":
        raise ValueError("not an MZ executable")
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\0\0":
        raise ValueError("PE signature missing")
    coff = pe_off + 4
    machine, nsects, timestamp, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", data, coff)
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<I", data, opt + 28)[0]
    size_image = struct.unpack_from("<I", data, opt + 56)[0]
    sections = []
    sh = opt + opt_size
    for i in range(nsects):
        off = sh + i * 40
        name = data[off:off + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vsize, rva, raw_size, raw_off, _, _, _, _, sec_chars = struct.unpack_from("<IIIIIIHHI", data, off + 8)
        sections.append({
            "name": name,
            "rva": rva,
            "va": image_base + rva,
            "virtual_size": vsize,
            "raw_size": raw_size,
            "raw_offset": raw_off,
            "characteristics": sec_chars,
        })
    return {
        "machine": machine,
        "number_of_sections": nsects,
        "timestamp": timestamp,
        "characteristics": chars,
        "optional_magic": magic,
        "image_base": image_base,
        "entry_rva": entry_rva,
        "entry_va": image_base + entry_rva,
        "size_of_image": size_image,
        "sections": sections,
    }


def va_to_file(pe: dict, va: int) -> int:
    rva = va - pe["image_base"]
    for s in pe["sections"]:
        extent = max(s["virtual_size"], s["raw_size"])
        if s["rva"] <= rva < s["rva"] + extent:
            return s["raw_offset"] + (rva - s["rva"])
    raise ValueError(f"VA 0x{va:08x} is not file-backed")


def main() -> None:
    data = BINARY.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(f"unexpected ecomppc.exe SHA-256: {digest}")

    pe = parse_pe(data)
    funcs = read_tsv(INVENTORY)
    func_by_va = {int(r["entry"], 16): r for r in funcs}

    with (OUT / "backend_functions.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["va", "rva", "name", "body_size", "caller_refs", "callee_count", "role", "evidence"])
        for va, (role, evidence) in FUNCTION_ROLES.items():
            r = func_by_va.get(va, {})
            w.writerow([
                f"0x{va:08x}", f"0x{va - pe['image_base']:08x}", r.get("name", role),
                r.get("body_size", ""), r.get("caller_refs", ""), r.get("callee_count", ""), role, evidence,
            ])

    vtable_rows = []
    for slot in range(0, BACKEND_VTABLE_SPAN, 8):
        pos = va_to_file(pe, BACKEND_VTABLE + slot)
        this_adjust, target = struct.unpack_from("<II", data, pos)
        row = func_by_va.get(target, {})
        method_offset = slot + 4
        vtable_rows.append({
            "record_offset": f"0x{slot:03x}",
            "method_offset": f"0x{method_offset:03x}",
            "this_adjust": this_adjust,
            "target_va": f"0x{target:08x}",
            "function_name": row.get("name", ""),
            "body_size": row.get("body_size", ""),
            "known_role": VTABLE_ROLES.get(method_offset, ""),
        })
    with (OUT / "target_vtable.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(vtable_rows[0]))
        w.writeheader()
        w.writerows(vtable_rows)

    string_rows = []
    seen = set()
    for r in read_tsv(STRINGS):
        s = r["string"]
        if not PPC_STRING_RE.search(s):
            continue
        key = (r["string_addr"], s, r["xref_from"], r["function_entry"])
        if key in seen:
            continue
        seen.add(key)
        string_rows.append({
            "string_va": "0x" + r["string_addr"].lower(),
            "string": s,
            "xref_from": ("0x" + r["xref_from"].lower()) if r["xref_from"] else "",
            "function_entry": ("0x" + r["function_entry"].lower()) if r["function_entry"] else "",
            "function_name": r["function_name"],
        })
    with (OUT / "ppc_strings.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["string_va", "string", "xref_from", "function_entry", "function_name"])
        w.writeheader()
        w.writerows(string_rows)

    summary = {
        "binary": str(BINARY.relative_to(ROOT)),
        "sha256": digest,
        "pe": pe,
        "imports": ["WS2_32.dll", "NETAPI32.dll", "MPR.dll", "KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"],
        "ghidra_function_count": len(funcs),
        "ghidra_thunk_count": sum(r["thunk"] == "true" for r in funcs),
        "functions_body_size_le_5": sum(int(r["body_size"]) <= 5 for r in funcs),
        "functions_body_size_le_16": sum(int(r["body_size"]) <= 16 for r in funcs),
        "entry_chain": {
            "pe_entry_va": "0x00a938ff",
            "security_cookie_init": "0x00aa424c",
            "crt_startup": "0x00a937ad",
            "probable_program_main_wrapper": "0x00995fd0",
            "compiler_bootstrap": "0x005b99a2",
        },
        "backend_object": {
            "global": f"0x{BACKEND_GLOBAL:08x}",
            "constructor": f"0x{BACKEND_CTOR:08x}",
            "allocation_size": "0x251c",
            "final_vtable": f"0x{BACKEND_VTABLE:08x}",
            "vtable_span_bytes": BACKEND_VTABLE_SPAN,
            "vtable_record_size": 8,
            "vtable_records": len(vtable_rows),
            "concrete_method_records_after_metadata": len(vtable_rows) - 1,
        },
        "structured_outputs": {
            "backend_functions": "backend_functions.csv",
            "target_vtable": "target_vtable.csv",
            "ppc_strings": "ppc_strings.csv",
        },
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(f"wrote {len(FUNCTION_ROLES)} key functions")
    print(f"wrote {len(vtable_rows)} target-vtable records")
    print(f"wrote {len(string_rows)} PPC/backend string rows")
    print(f"Ghidra functions: {len(funcs)}")


if __name__ == "__main__":
    main()
