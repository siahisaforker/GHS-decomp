#!/usr/bin/env python3
"""Build AI-ingestion manifests for the PPC emitter seam.

All addresses are normalized lower-case VAs. Observed facts and inferred
hypotheses are emitted separately. This script derives metadata only.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
BINARY = ROOT / "ghs5.3.22/bin/ecomppc.exe"
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
STRINGS = ROOT / "analysis/ghidra/out/all_string_xrefs.tsv"
SOURCES = ROOT / "analysis/prime/source_file_function_map.tsv"
OPTIONS = ROOT / "analysis/manual/internal_option_ids.tsv"
VTABLE = ROOT / "analysis/backend_map/target_vtable.csv"
OPTION_BASE = 0x00C4064E
EXPECTED_SHA256 = "b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3"


def hx(value: int) -> str:
    return f"0x{value:08x}"


# va, proposed_name, role, confidence, evidence_kind, evidence_refs
HYPOTHESES = [
    (0x006AE05C, "codewrite", "generic final-codewrite stage; invokes PPC target +0x5e4 before procedure output", 0.995, "decompile;vtable_dispatch;callgraph", "analysis/ghidra/out/keypasses/006ae05c_codewrite.c;target_slot:0x5e4;callee:0x004f5247"),
    (0x00408B78, "walk_instruction_or_operand", "generic instruction/operand walker used by register-mask visitor", 0.94, "callsite;decompile", "0x00423138;analysis/ppc_emitter/decompiled/00408b78_walk_instruction_or_operand.c"),
    (0x0042226D, "collect_register_change_classes", "classify operand registers into three 96-bit masks", 0.98, "decompile;dataflow", "analysis/ppc_emitter/decompiled/0042226d_regchgmask_mark_operand.c;0x00bdb560;0x00bdb56c;0x00bdb578"),
    (0x00422E2D, "register_change_mask_visitor", "walker callback that discovers changed registers", 0.98, "decompile;callsite", "analysis/ppc_emitter/decompiled/00422e2d_regchgmask_instruction_visit.c;0x00423138"),
    (0x00422F2E, "rpx_tnt_register_metadata_cleanup", "optional pre-finalization cleanup for register metadata", 0.91, "option_gate;decompile", "option:1800;analysis/ppc_emitter/decompiled/00422f2e_pre_emit_helper.c"),
    (0x00422FF4, "finalize_register_change_mask", "target slot +0x5e4; construct/finalize per-procedure register-change mask", 0.995, "vtable_slot;decompile;option_gate;bitset_ops", "target_slot:0x5e4;analysis/ppc_emitter/finalizer_regions.csv;option:1326"),
    (0x00423965, "target_operand_size_4_or_8", "return 4 or 8 from operand/type width comparison", 0.78, "vtable_slot;decompile", "target_slot:0x5cc;analysis/ppc_emitter/decompiled/00423965_post_emit_helper_0.c"),
    (0x00423991, "target_operand_size_16_or_32", "return 16 or 32 for a 64-bit/special operand case", 0.76, "vtable_slot;decompile", "target_slot:0x5d4;analysis/ppc_emitter/decompiled/00423991_post_emit_helper_1.c"),
    (0x00423AA1, "target_select_fsel_isel_legality", "predicate for fsel/isel style operand lowering", 0.86, "vtable_slot;option_gate;decompile", "target_slot:0x62c;option:1958;option:2581"),
    (0x00423C13, "target_register_class_selector", "select target register-class data with AltiVec/e500 exceptions", 0.78, "vtable_slot;option_gate;decompile", "target_slot:0x624;option:2062;option:2746"),
    (0x00423CAF, "target_register_number_table_lookup", "bounds-checked signed-short target register mapping lookup", 0.82, "vtable_slot;decompile", "target_slot:0x64c;analysis/ppc_emitter/decompiled/00423caf_ppc_target_cb_64c.c"),
    (0x00423CE7, "extended_asm_register_mask", "build legal register mask for extended-asm register classes", 0.97, "vtable_slot;string;decompile", "target_slot:0x5ec;string:Unsupported_Extended_Asm_register;analysis/ppc_emitter/decompiled/00423ce7_ppc_target_cb_5ec.c"),
    (0x00423E2D, "extended_asm_constraint_classifier", "classify I/U/X extended-asm constraints", 0.94, "vtable_slot;decompile", "target_slot:0x604;analysis/ppc_emitter/decompiled/00423e2d_ppc_target_cb_604.c"),
    (0x004242C0, "emit_ppc64_traceback_bytes", "emit textual PPC64 traceback-table bytes", 0.96, "vtable_slot;option_gate;output_calls", "target_slot:0x674;option:539;option:542"),
    (0x004244C6, "lower_relocatable_ppc_ir", "target +0x7ac callback; rewrite symbolic/address-bearing PPC IR into encodable target operations", 0.93, "vtable_slot;decompile;ir_rewrite", "target_slot:0x7ac;analysis/ppc_emitter/decompiled/004244c6_ppc_large_target_callback.c"),
    (0x0045FC7D, "ppc_local_peephole", "large PPC local peephole dispatcher; Espresso subpasses run first in fixed order", 0.995, "decompile;option_gate;string_xref", "option:937;option:4725;analysis/ghidra/out/decompiled/0045fc7d_FUN_0045fc7d.c"),
    (0x00476DA3, "ppc_target_initialize", "initialize PPC target globals/opcode registry and default-enable Nintendo paired-single optimizations", 0.995, "decompile;option_defaults;callee_graph", "callee:0x00491eb5;analysis/ppc_emitter/target_default_options.csv"),
    (0x0045EA8D, "espresso_combine_merge_helper", "paired-single combine/merge optimization helper", 0.96, "string_xref", "string:PS COM MERGE1;string:PS COM MERGE2;string:PS COM NEW"),
    (0x0045EC4A, "espresso_combine_load_helper", "paired-single load combine optimization helper", 0.96, "string_xref", "string:PS LOAD NEW;string:PS LOAD OLD1"),
    (0x0045F169, "espresso_combine_store_helper", "paired-single store combine optimization helper", 0.96, "string_xref", "string:PS ST NEW;string:PS ST OLD STFS1"),
    (0x0045F7E5, "espresso_fsplat_helper", "paired-single fsplat optimization helper", 0.96, "string_xref", "string:OLD PS FSPLAT;string:NEW PS FSPLAT"),
    (0x0045F976, "espresso_cmp_helper", "paired-single compare optimization helper", 0.95, "string_xref;decompile", "string:PS CMP OLD;string:PS CMP NEW"),
    (0x0045FC7D, "espresso_peephole_dispatcher", "ordered PPC local-peephole dispatcher for Espresso combine/store/load/fsplat/cmp helpers", 0.995, "option_gate;callgraph;string_xref", "option:4725;option:4712;option:4713;option:4714;option:4726;option:4728;analysis/ppc_emitter/espresso_peephole_order.csv"),
    (0x00476DA3, "initialize_ppc_target_options_and_opcodes", "initialize PPC target defaults, enable Espresso suboptions, and build fixed opcode registry", 0.995, "decompile;option_write;callgraph", "callee:0x00491eb5;option:4711;option:4715;option:4725;option:4712;option:4713;option:4714;option:4726;option:4728;option:4729;option:4997"),
    (0x0047E00E, "print_ppc_operand", "recursive PPC textual operand/relocation printer", 0.98, "decompile;output_calls", "analysis/ppc_emitter/decompiled/0047e00e_asm_instruction_printer.c"),
    (0x0047F1A6, "emit_ppc_instruction", "per-instruction output split between text assembly and binary object encoding", 0.995, "option_gate;decompile;callgraph", "option:75;callee:0x00497b18;analysis/ppc_emitter/decompiled_output/0047f1a6_ppc_instruction_text_or_object_emitter.c"),
    (0x00491DC0, "register_opcode_descriptor", "insert mnemonic/base-word/format descriptor into 255-bucket hash table", 0.995, "decompile;data_structure", "analysis/ppc_emitter/decompiled/00491dc0_ppc_opcode_register_entry.c;0x00bdae18"),
    (0x00491EB5, "initialize_ppc_opcode_table", "register 572 fixed PPC opcode descriptors including Espresso paired-single encodings", 0.999, "decompile;string_xref;constant_table", "analysis/ppc_emitter/opcode_table.csv;analysis/ppc_emitter/decompiled/00491eb5_ppc_opcode_table_init.c"),
    (0x004952B8, "insert_instruction_field", "mask and insert one value into a selected bitfield of a 32-bit PPC instruction word", 0.999, "decompile;bitfield_primitive", "caller:0x00495fc4;caller:0x00496041;caller:0x004960f6;caller:0x004962cb"),
    (0x004952D9, "resolve_operand_value", "resolve immediate/symbol/relocation value for binary encoder", 0.91, "decompile;callee_graph", "analysis/ppc_emitter/decompiled_output/004952d9_resolve_operand_value.c;caller:0x00497b18"),
    (0x00495D19, "map_register_number", "map IR register operand to encoded 5-bit PPC register number", 0.99, "decompile;field_packer_use", "analysis/ppc_emitter/decompiled_output/00495d19_map_register_number.c"),
    (0x00495FC4, "encode_d_form", "pack D-form fields and emit one 32-bit instruction word", 0.999, "decompile;bitfield_positions;output_call", "bits:21:5,16:5,0:16;callee:0x004e5aad"),
    (0x00496041, "encode_psq_d_form", "pack Espresso psq D-form including W/I fields", 0.999, "decompile;opcode_table", "format:0xa3;bits:21:5,16:5,0:12,15:1,12:3"),
    (0x004960F6, "encode_psq_x_form", "pack Espresso psq indexed form including W/I fields", 0.999, "decompile;opcode_table", "format:0xa4;bits:21:5,16:5,11:5,10:1,7:3"),
    (0x004961AB, "encode_branch_i_form", "pack PPC I-form branch displacement", 0.99, "decompile;bitfield_positions", "shift:2;width:24"),
    (0x004961F7, "encode_branch_b_form", "pack PPC B-form BO/BI and branch displacement", 0.98, "decompile;bitfield_positions", "bits:18:3;disp_shift:2;width:14"),
    (0x004962CB, "encode_x_form", "pack three 5-bit PPC X-form fields", 0.999, "decompile;bitfield_positions", "bits:21:5,16:5,11:5"),
    (0x00496348, "encode_rotate_mask_form", "pack split PPC rotate/mask fields", 0.99, "decompile;bitfield_positions", "analysis/ppc_emitter/decompiled_output/00496348_encode_rotate_mask_form.c"),
    (0x004964AA, "encode_multi_field_form", "pack five PPC instruction fields", 0.99, "decompile;bitfield_positions", "bits:21:5,16:5,11:5,6:5,1:5"),
    (0x004969E6, "lookup_opcode_descriptor", "construct final mnemonic spelling and hash-lookup encoding descriptor", 0.995, "decompile;hash_table", "hash_table:0x00bdae18;analysis/ppc_emitter/decompiled_output/004969e6_lookup_opcode_descriptor.c"),
    (0x00497B18, "encode_ppc_object_instruction", "binary/object PPC instruction encoder dispatching by descriptor format id", 0.999, "decompile;opcode_table;option_gate", "option:1346;descriptor_lookup:0x004969e6"),
    (0x0049A873, "ppc_relocation_adjust", "target +0x7b4 callback; adjust PPC relocation field offset/width and selected relocation kinds before generic object relocation creation", 0.94, "vtable_slot;decompile;relocation_path", "target_slot:0x7b4;caller:0x004e76f6;analysis/ppc_emitter/decompiled/0049a873_ppc_relocation_adjust.c"),
    (0x004E5AAD, "write_object_word", "write one 32-bit word using output endianness/object mode", 0.995, "decompile;option_gate", "option:75;option:78;analysis/ppc_emitter/decompiled/004e5aad_write_object_word.c"),
    (0x004E57E7, "write_object_halfword", "write one 16-bit halfword to text/object output with target endianness", 0.99, "decompile;option_gate;output_path", "option:75;option:78;analysis/ppc_emitter/decompiled/004e57e7_write_object_halfword.c"),
    (0x004E76F6, "add_object_relocation", "create object relocation records for symbolic PPC operands", 0.97, "decompile;relocation_calls", "analysis/ppc_emitter/decompiled/004e76f6_add_object_relocation.c"),
    (0x004F5247, "write_compiled_procedure", "iterate final instructions and send each to target output routine", 0.97, "decompile;callgraph", "callee:0x0047f1a6;analysis/ppc_emitter/decompiled/004f5247_post_codegen_metrics_or_stats.c"),
    (0x006A60DD, "dump_machine_code_marker", "optional text marker around machine-code diagnostic output", 0.93, "decompile;option_gate", "option:75;analysis/ppc_emitter/decompiled/006a60dd_dump_machine_code.c"),
    (0x0062375B, "advance_output_position", "advance emitted-code position and debug/output accounting before each encoded instruction word", 0.99, "decompile;encoder_callgraph", "callee_from:0x00495fc4;analysis/ppc_emitter/decompiled/0062375b_advance_output_location.c"),
    (0x006CE39F, "direct_c20asm_prepass", "mark repeated direct C2.0 asm nodes before final output", 0.9, "decompile;option_gate", "option:3377;analysis/ppc_emitter/decompiled/006ce39f_direct_c20asm_helper.c"),
    (0x0074281B, "generic_indopc_encode_dispatch", "generic opcode interface dispatch; target encode then optional text conversion/binary callback", 0.96, "source_path;decompile;option_gate", "src/compilers/indep/indopc.cc;option:75;analysis/ppc_emitter/decompiled/0074281b_indopc_encode_dispatch.c"),
]


def inventory() -> dict[int, dict[str, str]]:
    with FUNCTIONS.open(newline="", encoding="utf-8") as f:
        return {int(r["entry"], 16): r for r in csv.DictReader(f, delimiter="\t")}


def option_names() -> dict[int, str]:
    with OPTIONS.open(newline="", encoding="utf-8") as f:
        return {int(r["id"]): r["name"] for r in csv.DictReader(f, delimiter="\t")}


def source_map() -> dict[int, list[str]]:
    out: dict[int, list[str]] = defaultdict(list)
    with SOURCES.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            out[int(r["function_entry"], 16)].append(r["source_file"])
    return out


def string_map() -> dict[int, list[str]]:
    out: dict[int, list[str]] = defaultdict(list)
    with STRINGS.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f, delimiter="\t"):
            if not r["function_entry"]:
                continue
            out[int(r["function_entry"], 16)].append(
                f"{hx(int(r['string_addr'],16))}:{r['string']}"
            )
    return out


def vtable_map() -> dict[int, list[str]]:
    out: dict[int, list[str]] = defaultdict(list)
    with VTABLE.open(newline="", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["target_va"]:
                out[int(r["target_va"], 16)].append(r["method_offset"])
    return out


def decompile_for(va: int) -> Path | None:
    for directory in (OUT / "decompiled", OUT / "decompiled_output"):
        matches = sorted(directory.glob(f"{va:08x}_*.c"))
        if matches:
            return matches[0]
    return None


def option_refs_for(va: int, names: dict[int, str]) -> list[str]:
    path = decompile_for(va)
    if path is None:
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    result = []
    for raw in sorted(set(re.findall(r"DAT_00(c4[0-9a-f]{4})", text, re.I))):
        address = int(raw, 16)
        option_id = address - OPTION_BASE
        if option_id >= 0:
            result.append(f"{option_id}:{names.get(option_id,'?')}:{hx(address)}")
    return result


def direct_calls(inv: dict[int, dict[str, str]], selected: set[int]) -> tuple[dict[int, set[int]], dict[int, set[int]]]:
    proc = subprocess.run(["objdump", "-d", "-Mintel", str(BINARY)], check=True, text=True, stdout=subprocess.PIPE)
    ranges = sorted((int(r["body_min"],16), int(r["body_max"],16), va) for va,r in inv.items())
    callers: dict[int, set[int]] = defaultdict(set)
    callees: dict[int, set[int]] = defaultdict(set)
    owner_index = 0
    for line in proc.stdout.splitlines():
        match = re.match(r"\s*([0-9a-f]+):.*\bcall\s+(?:DWORD PTR )?(?:0x)?([0-9a-f]+)\b", line)
        if not match:
            continue
        site, target = int(match.group(1),16), int(match.group(2),16)
        while owner_index + 1 < len(ranges) and ranges[owner_index][1] < site:
            owner_index += 1
        owner = ranges[owner_index][2] if ranges[owner_index][0] <= site <= ranges[owner_index][1] else None
        if owner in selected:
            callees[owner].add(target)
        if target in selected and owner is not None:
            callers[target].add(owner)
    return callers, callees


def write_function_map() -> None:
    inv = inventory()
    names = option_names()
    sources = source_map()
    strings = string_map()
    vtables = vtable_map()
    selected = {row[0] for row in HYPOTHESES}
    callers, callees = direct_calls(inv, selected)
    fields = [
        "va","raw_name","proposed_name","role","confidence","evidence_kinds",
        "evidence_refs","provenance","body_end","body_size","source_files",
        "callers","callees","option_refs","string_refs","vtable_slots",
    ]
    with (OUT / "function_map.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for va, proposed, role, confidence, kinds, refs in sorted(HYPOTHESES):
            row = inv[va]
            w.writerow({
                "va": hx(va),
                "raw_name": row["name"],
                "proposed_name": proposed,
                "role": role,
                "confidence": f"{confidence:.3f}",
                "evidence_kinds": kinds,
                "evidence_refs": refs,
                "provenance": "analysis/ppc_emitter/build_ai_manifest.py",
                "body_end": "0x" + row["body_max"].lower(),
                "body_size": row["body_size"],
                "source_files": ";".join(sorted(sources.get(va, []))),
                "callers": ";".join(hx(x) for x in sorted(callers.get(va, []))),
                "callees": ";".join(hx(x) for x in sorted(callees.get(va, []))),
                "option_refs": ";".join(option_refs_for(va, names)),
                "string_refs": ";".join(sorted(strings.get(va, []))[:64]),
                "vtable_slots": ";".join(sorted(vtables.get(va, []))),
            })


def write_observed_facts() -> int:
    facts: list[dict[str, object]] = []
    with (OUT / "opcode_table.csv").open(newline="", encoding="utf-8") as f:
        opcodes = list(csv.DictReader(f))
    paired_single_count = sum(
        1 for row in opcodes if row["mnemonic"].startswith(("ps_", "psq_"))
    )
    def add(va: int, kind: str, value: object, refs: list[str], provenance: str) -> None:
        facts.append({
            "va": hx(va), "fact_kind": kind, "value": value,
            "evidence_refs": refs, "provenance": provenance,
        })
    add(0x00422FF4, "target_vtable_slot", {"method_offset":"0x5e4","record_offset":"0x5e0"}, ["analysis/backend_map/target_vtable.csv"], "analysis/backend_map/target_vtable.csv")
    for option_id in (1800,1326,1373,385,2942,3077):
        add(0x00422FF4, "option_reference", {"option_id":option_id,"option_byte_va":hx(OPTION_BASE+option_id)}, ["analysis/ppc_emitter/decompiled/00422ff4_ppc_final_emitter.c"], "analysis/ppc_emitter/decompiled/00422ff4_ppc_final_emitter.c")
    add(0x00491EB5, "opcode_descriptor_count", 572, ["analysis/ppc_emitter/opcode_table.csv"], "analysis/ppc_emitter/build_output_map.py")
    add(0x00491EB5, "paired_single_descriptors", paired_single_count, ["analysis/ppc_emitter/opcode_table.csv"], "analysis/ppc_emitter/opcode_table.csv")
    add(0x00496041, "encoding_format", {"format_id":"0xa3","fields":["21:5","16:5","0:12","15:1","12:3"]}, ["analysis/ppc_emitter/decompiled_output/00496041_encode_psq_d_form.c"], "analysis/ppc_emitter/decompiled_output/00496041_encode_psq_d_form.c")
    add(0x004960F6, "encoding_format", {"format_id":"0xa4","fields":["21:5","16:5","11:5","10:1","7:3"]}, ["analysis/ppc_emitter/decompiled_output/004960f6_encode_psq_x_form.c"], "analysis/ppc_emitter/decompiled_output/004960f6_encode_psq_x_form.c")
    add(0x0047F1A6, "output_gate", {"option_id":75,"name":"obj","zero":"text_assembly","nonzero":"binary_object"}, ["analysis/ppc_emitter/decompiled_output/0047f1a6_ppc_instruction_text_or_object_emitter.c"], "analysis/ppc_emitter/decompiled_output/0047f1a6_ppc_instruction_text_or_object_emitter.c")
    add(0x00497B18, "binary_encoder_invariant", {"option_id":1346,"name":"elfobj","required_nonzero":True}, ["analysis/ppc_emitter/decompiled_output/00497b18_ppc_object_instruction_encoder.c"], "analysis/ppc_emitter/decompiled_output/00497b18_ppc_object_instruction_encoder.c")
    add(0x004E5AAD, "endianness_gate", {"option_id":78,"name":"bigendian"}, ["analysis/ppc_emitter/decompiled/004e5aad_write_object_word.c"], "analysis/ppc_emitter/decompiled/004e5aad_write_object_word.c")
    add(0x0074281B, "source_file", "src/compilers/indep/indopc.cc", ["analysis/prime/source_file_function_map.tsv"], "analysis/prime/source_file_function_map.tsv")
    add(0x00494A21, "oracle_opcode_match", {"mnemonic":"ps_merge10","format_id":"0x23","base_encoding":"0x100004a0"}, ["analysis/oracle/_ps_probe/ps.s","analysis/ppc_emitter/oracle_opcode_matches.csv"], "analysis/ppc_emitter/oracle_opcode_matches.csv")
    facts.sort(key=lambda row: (row["va"], row["fact_kind"], json.dumps(row["value"], sort_keys=True)))
    with (OUT / "observed_facts.jsonl").open("w", encoding="utf-8") as f:
        for row in facts:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    return len(facts)


def write_hypotheses() -> int:
    rows = []
    inv = inventory()
    for va, proposed, role, confidence, kinds, refs in sorted(HYPOTHESES):
        rows.append({
            "va": hx(va),
            "raw_name": inv[va]["name"],
            "proposed_name": proposed,
            "role": role,
            "confidence": confidence,
            "evidence_kinds": kinds.split(";"),
            "evidence_refs": refs.split(";"),
            "provenance": "analysis/ppc_emitter/build_ai_manifest.py",
        })
    with (OUT / "hypotheses.jsonl").open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    return len(rows)


def write_checkpoint(facts: int, hypotheses: int) -> None:
    checkpoint = {
        "schema_version": 1,
        "target": {"path":"ghs5.3.22/bin/ecomppc.exe","sha256":EXPECTED_SHA256},
        "completed": [
            "partitioned target slot 0x5e4 / va 0x00422ff4",
            "identified obj text-vs-object split at 0x0047f1a6",
            "recovered 572-entry PPC opcode descriptor registry",
            "recovered binary encoder 0x00497b18 and field packers",
            "matched oracle assembly mnemonics to opcode descriptors",
            "mapped paired-single Espresso opcode formats 0xa3 and 0xa4",
        ],
        "counts": {"observed_facts":facts,"hypotheses":hypotheses,"opcode_descriptors":572},
        "resume": {
            "priority": 1,
            "next_va": "0x00497b18",
            "task": "partition remaining format-id switch cases and map every format id to field-packer semantics",
            "then": [
                "resolve target vtable relocation callback at slot +0x7b4 used by 0x004e76f6",
                "trace callers of Espresso helpers 0x0045ea8d..0x0045f976 back to exact option gates 4712-4728",
                "add object fixture relocation comparisons against normal cxppc output",
            ],
        },
        "generators": [
            "analysis/ppc_emitter/build_output_map.py",
            "analysis/ppc_emitter/build_ai_manifest.py",
        ],
    }
    (OUT / "checkpoint.json").write_text(json.dumps(checkpoint, indent=2, sort_keys=True)+"\n", encoding="utf-8")


def main() -> None:
    facts = write_observed_facts()
    hypotheses = write_hypotheses()
    write_function_map()
    write_checkpoint(facts, hypotheses)
    print(f"wrote ai manifest: {facts} facts, {hypotheses} hypotheses")


if __name__ == "__main__":
    main()
