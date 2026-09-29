#!/usr/bin/env python3
"""Regenerate the concrete PPC output/encoding map for ecomppc.exe.

Only derived metadata is written: function addresses, option gates, opcode
names/format IDs/base words, semantic regions, and oracle mnemonic matches.
No executable bytes are copied into the generated files.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
BINARY = ROOT / "ghs5.3.22/bin/ecomppc.exe"
ANCHORS = ROOT / "analysis/manual/ecomppc_static_anchors.json"
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
OPTION_IDS = ROOT / "analysis/manual/internal_option_ids.tsv"
EXPECTED_SHA256 = "b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3"
OPTION_BASE = 0x00C4064E


# address, analysis label, role, confidence, evidence
FUNCTION_ROLES = [
    (0x0045EA8D, "espresso_combine_merge", "Espresso peephole: replace compatible paired-single merge chain with internal paired-single merge op", "high", "gated by espresso_combine_merge in 0x0045fc7d; PS_COM_* diagnostics"),
    (0x0045EC4A, "espresso_combine_load", "Espresso peephole: combine compatible scalar/load sequence into internal paired-single load op", "high", "gated by espresso_combine_load in 0x0045fc7d; PS_LOAD_* diagnostics"),
    (0x0045F169, "espresso_combine_store", "Espresso peephole: combine compatible store/merge chain into internal paired-single store op", "high", "gated by espresso_combine_store in 0x0045fc7d; PS_ST_* diagnostics"),
    (0x0045F7E5, "espresso_fsplat", "Espresso peephole: fold splat-producing sequence into paired-single IR", "high", "gated by espresso_fsplat in 0x0045fc7d; PS_FSPLAT diagnostics"),
    (0x0045F976, "espresso_cmp", "Espresso peephole: combine comparison sequence into paired-single compare IR", "high", "gated by espresso_cmp in 0x0045fc7d; PS_CMP_* diagnostics"),
    (0x0045FC7D, "ppc_local_peephole", "large PPC local peephole dispatcher; Espresso subpasses run first in fixed order", "high", "direct tests of espresso_peepholes and five sub-gates"),
    (0x00476DA3, "ppc_target_initialize", "PPC target initialization: register target defaults/register numbering and enable Espresso tuning defaults", "high", "writes PPC register globals and Espresso option bytes"),
    (0x00408B78, "walk_instruction_or_operand", "generic instruction/operand walker used by register-mask visitor", "high", "direct call from 0x00422ff4"),
    (0x0042226D, "collect_register_change_classes", "classify operand register numbers into GPR/FPR/special 96-bit masks", "high", "writes 0x00bdb560/56c/578 using recovered register ranges"),
    (0x00422E2D, "register_change_mask_visitor", "walker callback that recurses through relevant instruction operands", "high", "direct callback argument from 0x00422ff4"),
    (0x00422F2E, "ppc_ep_rpx_tnt_cleanup", "optional pre-finalization cleanup of register metadata", "medium", "direct ppc_ep_rpx_tnt gate in 0x00422ff4"),
    (0x00422FF4, "finalize_register_change_mask", "target +0x5e4 callback; build/finalize procedure register-change mask", "high", "decompile + raw disassembly + option/register globals"),
    (0x00423CE7, "extended_asm_register_constraints", "target +0x5ec callback; construct legal register bitset for PPC extended-asm constraints", "high", "Unsupported Extended Asm register constraint diagnostic; ppcsfp-specific FPR range"),
    (0x00423E2D, "extended_asm_immediate_constraints", "target +0x604 callback; recognize/print PPC extended-asm I/U/X operand modifiers", "high", "literal constraint-letter switch and operand-kind checks"),
    (0x004242C0, "emit_ppc64_traceback_metadata", "target +0x674 callback; emit compact PPC64 traceback metadata bytes when ABI requires it", "medium-high", "linux_ppc64_abi && !ppc64_no_traceback_table gate; serializes eight state bytes"),
    (0x0047F1A6, "emit_ppc_instruction", "per-instruction output bifurcation: text assembly or binary object encoding", "high", "obj gate at function body; only caller into 0x00497b18"),
    (0x00491DC0, "register_opcode_descriptor", "insert mnemonic/base-word/format descriptor into 255-bucket hash table", "high", "descriptor fields and hash insertion at 0x00bdae18"),
    (0x00491EB5, "initialize_ppc_opcode_table", "register 572 fixed PPC mnemonic/format/base-word descriptors", "high", "572 direct calls to 0x00491dc0"),
    (0x004952D9, "resolve_operand_value", "resolve/evaluate operand or relocation-aware immediate used by encoder", "medium-high", "repeated object-encoder use before bitfield packers"),
    (0x00495D19, "map_register_number", "map compiler operand/register object to encoded register field value", "high", "encoder helper input to all register field packers"),
    (0x00495FC4, "encode_d_form", "pack RT/RS, RA and 16-bit immediate into base word and emit 4 bytes", "high", "field placements 21:5,16:5,0:16"),
    (0x00496041, "encode_psq_d_form", "pack paired-single quantized D-form including W/I fields and emit 4 bytes", "high", "format 0xa3 dispatch; fields 21:5,16:5,0:12,15:1,12:3"),
    (0x004960F6, "encode_psq_x_form", "pack paired-single quantized indexed form including W/I fields and emit 4 bytes", "high", "format 0xa4 dispatch; fields 21:5,16:5,11:5,10:1,7:3"),
    (0x004961AB, "encode_branch_i_form", "pack 24-bit relative branch displacement and emit 4 bytes", "high", "format 2/branch fallback use"),
    (0x004961F7, "encode_branch_b_form", "pack BO/BI plus 14-bit branch displacement and emit 4 bytes", "high", "branch format path"),
    (0x00496261, "encode_branch_xl_form", "pack branch-register fields and displacement form", "medium-high", "object encoder branch path"),
    (0x004962CB, "encode_x_form", "pack three 5-bit register/operand fields and emit 4 bytes", "high", "field placements 21:5,16:5,11:5"),
    (0x00496348, "encode_rotate_mask_form", "pack 64-bit rotate/mask split fields and emit 4 bytes", "high", "split high bits into instruction bit positions"),
    (0x004964AA, "encode_multi_field_form", "pack up to five 5-bit fields and emit 4 bytes", "high", "field placements 21/16/11/6/1"),
    (0x004969E6, "lookup_opcode_descriptor", "construct final mnemonic spelling and hash-lookup its opcode descriptor", "high", "hash lookup in 0x00bdae18; returns base word and format ID"),
    (0x00497B18, "encode_ppc_object_instruction", "binary PPC instruction encoder selected by obj output path", "high", "format switch over descriptor +4/+8; paired-single cases 0xa3/0xa4"),
    (0x004F5247, "write_compiled_procedure", "iterate machine procedures/instructions and invoke target instruction output", "high", "loops each procedure +0x50 instruction list and calls 0x0047f1a6"),
    (0x006A60DD, "dump_machine_code_marker", "optional textual diagnostic marker around machine-code dump", "high", "dump_mcode_everywhere path"),
    (0x006CE39F, "direct_c20asm_prepass", "preprocess/mark repeated direct C2.0 asm nodes before final output", "medium-high", "direct_c20asm gate; no text/object emission calls"),
]


# start, end_exclusive, label, gates/condition, semantic effect
FINALIZER_REGIONS = [
    (0x00422FF4, 0x0042301E, "optional_precleanup", "ppc_ep_rpx_tnt", "run 0x00422f2e metadata cleanup"),
    (0x0042301E, 0x00423031, "master_gate", "useregchgmask", "return immediately when register-change masks are disabled"),
    (0x00423031, 0x0042305A, "procedure_exclusions", "procedure predicates", "skip ineligible procedure forms and already-excluded state"),
    (0x0042305A, 0x00423092, "ada95_exclusion", "ada95", "invalidate mask-valid bit for special Ada procedure state"),
    (0x00423092, 0x00423153, "initialize_and_walk", "eligible procedure", "clear class masks, preserve old mask, walk instructions/operands"),
    (0x00423153, 0x00423833, "special_argument_registers", "!ajo1 && (codefactor || linkxda)", "add r3/r4 to GPR class mask; includes inlined bitset management"),
    (0x00423833, 0x00423960, "finalize_mask", "eligible procedure", "set valid bit and merge shifted GPR/FPR/special masks plus preserved mask into proc+0xb0"),
    (0x00423960, 0x00423965, "return", "always", "return from target callback"),
]


# Option gates with directly observed roles in this seam.
GATE_ROLES = [
    (937, "nolocalpeep", "0x0045fc7d", "master early return for PPC local peephole dispatcher"),
    (4712, "espresso_combine_merge", "0x0045fc7d", "gate 0x0045ea8d paired-single merge combiner"),
    (4713, "espresso_combine_load", "0x0045fc7d", "gate 0x0045ec4a paired-single load combiner"),
    (4714, "espresso_combine_store", "0x0045fc7d", "gate 0x0045f169 paired-single store combiner"),
    (4725, "espresso_peepholes", "0x0045fc7d", "master enable for Espresso-specific local peephole subpasses"),
    (4726, "espresso_fsplat", "0x0045fc7d", "gate 0x0045f7e5 paired-single splat combiner"),
    (4728, "espresso_cmp", "0x0045fc7d", "gate 0x0045f976 paired-single compare combiner"),
    (1800, "ppc_ep_rpx_tnt", "0x00422ff4", "pre-clean register metadata before mask reconstruction"),
    (1326, "useregchgmask", "0x00422ff4", "master enable for register-change-mask construction"),
    (1373, "ada95", "0x00422ff4", "special procedure exclusion invalidates register mask"),
    (385, "ajo1", "0x00422ff4", "suppresses explicit r3/r4 addition"),
    (2942, "codefactor", "0x00422ff4", "with !ajo1, causes r3/r4 addition"),
    (3077, "linkxda", "0x00422ff4", "with !ajo1, causes r3/r4 addition"),
    (75, "obj", "0x0047f1a6", "0 selects textual assembly; nonzero selects binary object encoder"),
    (1346, "elfobj", "0x00497b18", "required invariant for binary PPC object encoder"),
    (3377, "direct_c20asm", "0x006ae05c", "runs direct-C2.0-asm prepass 0x006ce39f before main output"),
    (696, "ppcvle", "0x0047f1a6/0x00497b18", "selects VLE-sensitive textual/object handling"),
    (542, "linux_ppc64_abi", "0x0047f1a6", "changes PPC64 textual relocation/operand spellings"),
    (539, "ppc64_no_traceback_table", "0x004242c0", "suppresses target +0x674 PPC64 traceback metadata output"),
    (542, "linux_ppc64_abi", "0x004242c0", "enables target +0x674 PPC64 traceback metadata output"),
    (1128, "ppcsfp", "0x0047f1a6/0x00497b18", "changes SFP instruction/output behavior"),
    (1200, "ppcabipic", "0x0047f1a6", "PIC ABI textual lowering/relocation spelling"),
    (1201, "ppclargegot", "0x0047f1a6", "large-GOT textual lowering"),
    (2062, "AltiVec", "0x004969e6", "permits alternate opcode descriptor path for vector instructions"),
]


ORACLE_FILES = [
    "analysis/oracle_local/t_asm.s",
    "analysis/oracle/_ps_probe/ps.s",
    "analysis/oracle/_ps_probe/vector__Ospeed__Ovector.s",
    "analysis/oracle/_ps_probe/vector_pragma__Ospeed__Ovector.s",
]


def hx(value: int) -> str:
    return f"0x{value:08x}"


def verify_binary() -> bytes:
    data = BINARY.read_bytes()
    actual = hashlib.sha256(data).hexdigest()
    if actual != EXPECTED_SHA256:
        raise SystemExit(f"unexpected ecomppc.exe sha256: {actual}")
    return data


def load_sections() -> list[dict[str, int]]:
    anchors = json.loads(ANCHORS.read_text(encoding="utf-8"))
    return anchors["sections"]


def va_to_file(va: int, sections: list[dict[str, int]]) -> int:
    for section in sections:
        start = section["va"]
        end = start + section["raw_size"]
        if start <= va < end:
            return section["raw_offset"] + va - start
    raise ValueError(f"VA is not file-backed: {va:#x}")


def read_c_string(data: bytes, va: int, sections: list[dict[str, int]]) -> str:
    offset = va_to_file(va, sections)
    end = data.find(b"\0", offset, offset + 256)
    if end < 0:
        raise ValueError(f"unterminated string at {va:#x}")
    return data[offset:end].decode("ascii", errors="replace")


def parse_instruction(line: str) -> tuple[int, str, str] | None:
    match = re.match(
        r"\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*([a-z][a-z0-9.]*)\s*(.*)$",
        line,
    )
    if not match:
        return None
    return int(match.group(1), 16), match.group(2), match.group(3).strip()


def extract_opcode_table(data: bytes, sections: list[dict[str, int]]) -> list[dict[str, object]]:
    proc = subprocess.run(
        [
            "objdump",
            "-d",
            "-Mintel",
            "--start-address=0x00491eb5",
            "--stop-address=0x00494bbb",
            str(BINARY),
        ],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
    )
    instructions = [item for line in proc.stdout.splitlines() if (item := parse_instruction(line))]
    rows: list[dict[str, object]] = []
    for index, (address, mnemonic, operand) in enumerate(instructions):
        if mnemonic != "call" or operand != "0x491dc0" or index < 3:
            continue
        previous = instructions[index - 3 : index]
        if any(item[1] != "push" for item in previous):
            continue
        try:
            base_encoding = int(previous[0][2], 16)
            format_id = int(previous[1][2], 16)
            string_va = int(previous[2][2], 16)
        except ValueError:
            continue
        rows.append(
            {
                "callsite": hx(address),
                "mnemonic": read_c_string(data, string_va, sections),
                "format_id": format_id,
                "format_id_hex": f"0x{format_id:x}",
                "base_encoding": hx(base_encoding),
                "string_va": hx(string_va),
            }
        )
    if len(rows) != 572:
        raise SystemExit(f"expected 572 fixed opcode registrations, found {len(rows)}")
    return rows


def write_opcode_table(rows: list[dict[str, object]]) -> None:
    # Keep this secondary/raw-disassembly view separate from build_map.py's
    # canonical opcode_table.csv.  The two tables intentionally have different
    # schemas and must not overwrite one another when both generators run.
    with (OUT / "output_opcode_table.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def function_inventory() -> dict[int, dict[str, str]]:
    with FUNCTIONS.open(newline="", encoding="utf-8") as f:
        return {int(row["entry"], 16): row for row in csv.DictReader(f, delimiter="\t")}


def write_function_map() -> None:
    inventory = function_inventory()
    confidence_values = {"high": 0.950, "medium-high": 0.850, "medium": 0.700}
    rows = []
    for address, name, role, confidence, evidence in FUNCTION_ROLES:
        row = inventory[address]
        rows.append(
            [
                hx(address),
                row["name"],
                name,
                role,
                f"{confidence_values[confidence]:.3f}",
                "decompile;static_analysis",
                evidence,
                "analysis/ppc_emitter/build_output_map.py",
                "0x" + row["body_max"],
                row["body_size"],
            ]
        )
    with (OUT / "output_function_map.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "va", "raw_name", "proposed_name", "role", "confidence",
            "evidence_kinds", "evidence_refs", "provenance", "end", "size",
        ])
        writer.writerows(rows)


def load_option_names() -> dict[int, str]:
    with OPTION_IDS.open(newline="", encoding="utf-8") as f:
        return {int(row["id"]): row["name"] for row in csv.DictReader(f, delimiter="\t")}


def write_gates() -> None:
    names = load_option_names()
    with (OUT / "output_gates.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["option_id", "option_name", "option_byte_va", "function", "observed_effect"])
        for option_id, expected_name, function, effect in GATE_ROLES:
            actual = names.get(option_id)
            if actual != expected_name:
                raise SystemExit(
                    f"option mismatch for {option_id}: expected {expected_name}, found {actual}"
                )
            writer.writerow([option_id, expected_name, hx(OPTION_BASE + option_id), function, effect])


def write_regions() -> None:
    with (OUT / "finalizer_regions.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "va", "end_exclusive", "raw_name", "proposed_name", "role",
            "confidence", "evidence_kinds", "evidence_refs", "provenance",
            "gate_or_condition",
        ])
        for start, end, label, gate, effect in FINALIZER_REGIONS:
            writer.writerow([
                hx(start), hx(end), "", label, effect, "0.970",
                "decompile;control_flow;option_gate",
                "analysis/ppc_emitter/decompiled/00422ff4_ppc_final_emitter.c",
                "analysis/ppc_emitter/build_output_map.py", gate,
            ])


def write_espresso_path() -> None:
    rows = [
        (0, "espresso_combine_store", 4714, "0x0045f169", "paired-single store combine"),
        (1, "espresso_combine_merge", 4712, "0x0045ea8d", "paired-single merge combine"),
        (2, "espresso_combine_load", 4713, "0x0045ec4a", "paired-single load combine"),
        (3, "espresso_fsplat", 4726, "0x0045f7e5", "paired-single splat fold"),
        (4, "espresso_cmp", 4728, "0x0045f976", "paired-single compare combine"),
    ]
    with (OUT / "espresso_peephole_order.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["order", "option_name", "option_id", "helper", "effect"])
        writer.writerows(rows)


def oracle_mnemonics(path: Path) -> set[str]:
    result: set[str] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ".", ";")) or stripped.endswith(":"):
            continue
        token = stripped.split(None, 1)[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", token):
            result.add(token)
    return result


def write_oracle_matches(opcodes: list[dict[str, object]]) -> None:
    by_name = {str(row["mnemonic"]): row for row in opcodes}
    with (OUT / "oracle_opcode_matches.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["fixture", "mnemonic", "format_id", "base_encoding", "opcode_callsite"])
        for relative in ORACLE_FILES:
            path = ROOT / relative
            if not path.exists():
                continue
            for mnemonic in sorted(oracle_mnemonics(path)):
                row = by_name.get(mnemonic)
                if row:
                    writer.writerow(
                        [
                            relative,
                            mnemonic,
                            row["format_id"],
                            row["base_encoding"],
                            row["callsite"],
                        ]
                    )


def write_summary(opcodes: list[dict[str, object]]) -> None:
    ps = [row for row in opcodes if str(row["mnemonic"]).startswith(("ps_", "psq_"))]
    summary = {
        "target": {
            "path": "ghs5.3.22/bin/ecomppc.exe",
            "sha256": EXPECTED_SHA256,
        },
        "target_vtable_slot_0x5e4": {
            "function": "0x00422ff4",
            "semantic_role": "finalize_register_change_mask",
            "raw_instruction_encoder": False,
        },
        "instruction_output_boundary": {
            "per_instruction_function": "0x0047f1a6",
            "text_assembly_condition": "obj == 0",
            "binary_object_condition": "obj != 0",
            "binary_encoder": "0x00497b18",
            "binary_encoder_requires": "elfobj != 0",
        },
        "opcode_database": {
            "initializer": "0x00491eb5",
            "register_function": "0x00491dc0",
            "hash_buckets": 255,
            "hash_bucket_array": "0x00bdae18",
            "fixed_descriptor_count": len(opcodes),
            "paired_single_descriptor_count": len(ps),
            "paired_single_format_ids": sorted(
                {f"0x{int(row['format_id']):x}" for row in ps}
            ),
        },
        "binary_encoder": {
            "descriptor_lookup": "0x004969e6",
            "descriptor_fields": {
                "+0x0": "mnemonic pointer",
                "+0x4": "32-bit base instruction word",
                "+0x8": "operand/encoding format id",
                "+0xc": "hash-chain next",
            },
            "write_pattern": "pack fields into base word, reserve 4 bytes, write word at current output location",
            "paired_single_quantized": {
                "format_0xa3": "0x00496041",
                "format_0xa4": "0x004960f6",
            },
        },
        "espresso_peepholes": {
            "dispatcher": "0x0045fc7d",
            "master_gate": "espresso_peepholes",
            "master_disable": "nolocalpeep",
            "ordered_helpers": [
                "0x0045f169 espresso_combine_store",
                "0x0045ea8d espresso_combine_merge",
                "0x0045ec4a espresso_combine_load",
                "0x0045f7e5 espresso_fsplat",
                "0x0045f976 espresso_cmp",
            ],
            "ppc_target_initializer": "0x00476da3",
            "initializer_sets_to_one": [
                "espresso_basic_ps_opt",
                "espresso_loadstore_opt",
                "espresso_peepholes",
                "espresso_combine_merge",
                "espresso_combine_load",
                "espresso_combine_store",
                "espresso_fsplat",
                "espresso_cmp",
                "espresso_ps_pre",
                "espresso_ps_structinreg",
            ],
        },
    }
    (OUT / "output_summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )


def main() -> None:
    data = verify_binary()
    sections = load_sections()
    opcodes = extract_opcode_table(data, sections)
    write_opcode_table(opcodes)
    write_function_map()
    write_gates()
    write_regions()
    write_espresso_path()
    write_oracle_matches(opcodes)
    write_summary(opcodes)
    print(
        f"wrote {len(opcodes)} opcodes, {len(FUNCTION_ROLES)} functions, "
        f"{len(GATE_ROLES)} option gates"
    )


if __name__ == "__main__":
    main()
