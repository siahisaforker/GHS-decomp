#!/usr/bin/env python3
"""Regenerate the focused PowerPC emitter map from local RE artifacts.

Outputs contain addresses, option names, opcode metadata, and oracle-derived
instruction words only.  No executable bytes or bulk decompiler text are copied.
"""

from __future__ import annotations

import csv
import bisect
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
BIN = ROOT / "ghs5.3.22/bin/ecomppc.exe"
EXPECTED_SHA256 = "b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3"
OPTION_BASE = 0x00C4064E


# Address, analysis label, role, confidence, evidence.
FUNCTIONS = [
    (0x006AE05C, "codewrite", "generic final-codewrite stage that invokes target slot +0x5e4", "high", "Ghidra decompile; target-vtable dispatch"),
    (0x00422FF4, "finalize_register_change_mask", "PPC target +0x5e4 callback; computes final 96-bit register-change metadata", "high", "option gates + six-word bitset operations + proc flag 0x80"),
    (0x00422F2E, "rpx_tnt_regmask_cleanup", "optional pre-finalization cleanup for ppc_ep_rpx_tnt", "medium-high", "direct call from 0x00422ff4 gated by ID 1800"),
    (0x00422E2D, "regchgmask_instruction_visit", "instruction/operand visitor callback used during final mask scan", "high", "passed to 0x00408b78 by 0x00422ff4"),
    (0x0042226D, "regchgmask_mark_operand", "maps visited target registers into three 96-bit working masks", "high", "called by 0x00422e2d; register-range globals and bit writes"),
    (0x00406399, "bitset_fill_96", "fill six 16-bit words with one value", "high", "loop count 6 over ushort words"),
    (0x00405D8A, "bitset_and_96", "AND six 16-bit words", "high", "six-word loop"),
    (0x00405DC1, "bitset_or_96", "OR six 16-bit words", "high", "six-word loop"),
    (0x00405DF8, "bitset_shift_left_96", "left-shift six-word/96-bit mask", "high", "six-word shift implementation"),
    (0x0047F1A6, "ppc_per_instruction_output", "per-instruction text-vs-object output dispatcher", "high", "obj gate: text path when clear; calls 0x00497b18 when set"),
    (0x0047E00E, "ppc_asm_operand_printer", "textual PPC operand/relocation printer", "high", "emits SDA/PID/TLS syntax and punctuation through text sinks"),
    (0x004F5247, "final_instruction_output_loop", "walk finalized blocks/instructions and invoke 0x0047f1a6 for each emitted operation", "high", "codewrite calls this after target +0x5e4; direct per-op call at decompile line 95"),
    (0x004816C0, "text_function_footer", "emit function/frame summary comments in assembly mode", "high", "obj==0 gate and #function/#stack frame strings"),
    (0x0074281B, "indopc_encode_dispatch", "generic indopc encoder interface: target opdata encoding plus text/object sink dispatch", "high", "embedded src/compilers/indep/indopc.cc breadcrumb; 4 KiB opdata buffer and obj gate"),
    (0x00497B18, "ppc_binary_instruction_output", "binary PPC encoder/relocation dispatcher for one IR instruction", "high", "opcode descriptor format switch; calls concrete form encoders"),
    (0x004969E6, "opcode_descriptor_for_ir", "lookup PPC opcode descriptor/base word/format for IR instruction", "high", "called immediately before format switch in binary encoder"),
    (0x00491EB5, "ppc_opcode_table_init", "register base PPC mnemonic/format/base-word table", "high", "572 calls to 0x00491dc0"),
    (0x00491DC0, "ppc_opcode_register", "insert mnemonic record into 255-bucket opcode hash table", "high", "allocates 16-byte record and hashes mnemonic"),
    (0x0049A9A0, "opcode_hash_contains", "test whether mnemonic already exists in opcode hash", "high", "hash+strcmp chain over DAT_00bdae18"),
    (0x0049AA41, "e500_opcode_extension_init", "conditionally add SPE/e500 opcode families", "high", "ppce500 gate; extension tables and opcode registration"),
    (0x00476DA3, "ppc_target_init", "initialize PPC target defaults and base opcode table", "high", "sets target option bytes and calls 0x00491eb5"),
    (0x004952D9, "resolve_immediate_or_reloc", "resolve operand value or create relocation-facing value", "medium-high", "used throughout binary form switch before bit packing"),
    (0x004952B8, "insert_instruction_field", "insert a value into a selected bitfield of a 32-bit PPC instruction word", "high", "shared primitive called by all recovered form encoders"),
    (0x00495D19, "encode_register_number", "map target register operand to encoded register number", "high", "feeds 5-bit fields in form encoders"),
    (0x00495FC4, "encode_d_form", "pack GPR/FPR fields + 16-bit immediate and emit 4-byte word", "high", "bit positions 21/16/0; output word sink"),
    (0x00496041, "encode_psq_d_form", "pack paired-single quantized D-form fields", "high", "bits 21:5,16:5,0:12,15:1,12:3"),
    (0x004960F6, "encode_psq_x_form", "pack paired-single quantized indexed-form fields", "high", "bits 21:5,16:5,11:5,10:1,7:3"),
    (0x004961AB, "encode_branch_i_form", "pack 24-bit word-aligned branch displacement", "high", "displacement shifted/masked then 4-byte output"),
    (0x004961F7, "encode_branch_b_form", "pack BO/condition plus 14-bit word-aligned branch displacement", "high", "bits 18:3 plus shifted displacement"),
    (0x00496261, "encode_branch_xl_form", "pack XL-style branch fields", "high", "5-bit field at bit16 plus 14-bit shifted value"),
    (0x004962CB, "encode_x_form", "pack three 5-bit register fields into X-form base word", "high", "bits 21/16/11 then 4-byte output"),
    (0x00496348, "encode_rotate_mask_form", "pack two registers plus split 6-bit rotate/mask fields", "high", "5-bit fields plus high-bit split positions"),
    (0x004964AA, "encode_multi_field_form", "pack five 5-bit fields into base word", "high", "bits 21/16/11/6/1"),
    (0x004E5AAD, "emit_u32_word", "serialize one 32-bit PPC word as .byte text or object bytes according to obj/bigendian", "high", "all recovered form encoders call this after advancing 4 bytes"),
    (0x0062375B, "advance_output_position", "advance emitted-code position and optional debug/output accounting", "high", "all recovered form encoders call with (4,1) before word sink"),
    (0x00423AA1, "target_predicate_62c", "PPC instruction predicate influenced by isel/fsel/vectorizer options", "medium-high", "target slot +0x62c and direct option tests"),
    (0x00423C13, "target_operand_class_624", "choose PPC operand/register class table for AltiVec/e500", "medium-high", "target slot +0x624; AltiVec/ppce500 gates"),
    (0x00423CE7, "target_extasm_regset_5ec", "construct extended-asm register-set bitmask", "medium-high", "target slot +0x5ec; ppcsfp gate"),
    (0x00423E2D, "target_extasm_constraint_604", "PPC extended-asm constraint printer/validator", "medium-high", "target slot +0x604; I/U/X constraint handling"),
    (0x004244C6, "target_relocatable_ir_lowering_7ac", "rewrite symbolic/address-bearing generic IR into PPC target operations before final encoding", "high", "target slot +0x7ac; decompile rewrites opcodes 0x78..0x7b and 0xc6/0xcd"),
    (0x00424C57, "target_branch_merge_834", "construct helper instruction during target branch merge", "medium-high", "target slot +0x834; creates opcode 0x85"),
    (0x0045FC7D, "ppc_local_peephole", "PPC local peephole dispatcher; Espresso subpasses run first in fixed order", "high", "espresso_peepholes and sub-option gates"),
    (0x0045EA8D, "espresso_combine_merge", "paired-single merge combiner", "high", "espresso_combine_merge gate; PS COM diagnostics"),
    (0x0045EC4A, "espresso_combine_load", "paired-single load combiner", "high", "espresso_combine_load gate; PS LOAD diagnostics"),
    (0x0045F169, "espresso_combine_store", "paired-single store combiner", "high", "espresso_combine_store gate; PS ST diagnostics"),
    (0x0045F7E5, "espresso_fsplat", "paired-single splat combiner", "high", "espresso_fsplat gate; PS FSPLAT diagnostics"),
    (0x0045F976, "espresso_cmp", "paired-single compare combiner", "high", "espresso_cmp gate; PS CMP diagnostics"),
    (0x0049A873, "ppc_relocation_adjust_7b4", "target relocation callback that adjusts field offset/width/type before generic relocation creation", "high", "target slot +0x7b4; first callback in 0x004e76f6"),
    (0x004E57E7, "emit_u16_halfword", "serialize one 16-bit halfword according to obj/bigendian", "high", "called by 0x004e5aad and binary pseudo-op paths"),
    (0x004E76F6, "add_object_relocation", "create generic object relocation records after target PPC relocation adjustment", "high", "binary encoder uses relocation IDs 10/11 for I/B branches"),
]


OPTION_GATES = [
    (0x00422FF4, 1800, "ppc_ep_rpx_tnt", "!= 0", "run 0x00422f2e cleanup before register-mask processing"),
    (0x00422FF4, 1326, "useregchgmask", "!= 0", "master enable for +0x5e4 register-change-mask finalizer"),
    (0x00422FF4, 1373, "ada95", "!= 0 with proc state byte +0x80", "suppress mask generation for selected Ada procedure state"),
    (0x00422FF4, 385, "ajo1", "== 0", "allow addition of two reserved/special register bits"),
    (0x00422FF4, 2942, "codefactor", "!= 0 (OR linkxda)", "enable special-register bit augmentation"),
    (0x00422FF4, 3077, "linkxda", "!= 0 (OR codefactor)", "enable special-register bit augmentation"),
    (0x0047F1A6, 75, "obj", "== 0", "emit textual assembly; nonzero selects binary/object encoder 0x00497b18"),
    (0x0074281B, 75, "obj", "== 0 on target-encode failure", "permit fallback to textual PPC operand printer; object mode treats failed target encoding as invalid"),
    (0x0074281B, 10, "consistent", "!= 0", "validate instruction/operand consistency before target encoding"),
    (0x00497B18, 1346, "elfobj", "!= 0", "required invariant for binary PPC instruction encoder"),
    (0x004E5AAD, 75, "obj", "== 0 vs != 0", "select .byte textual rendering versus binary section write"),
    (0x004E5AAD, 78, "bigendian", "!= 0", "serialize high byte/halfword first; matches Wii big-endian ELF output"),
    (0x00497B18, 1128, "ppcsfp", "== 0 for selected CR opcodes", "inject target CR helper encoding before main instruction"),
    (0x00497B18, 2686, "ppc_lwz_absol", "!= 0", "allow absolute D-form rewrite for qualifying loads"),
    (0x0049AA41, 2746, "ppce500", "!= 0", "register e500/SPE extension opcode families"),
    (0x00423AA1, 1958, "ppc_isel", "tested", "affects target instruction predicate"),
    (0x00423AA1, 2581, "ppc_fsel", "tested", "affects target instruction predicate"),
    (0x00423C13, 2062, "AltiVec", "tested", "selects vector operand/register class table"),
    (0x00423C13, 2746, "ppce500", "tested", "selects e500 operand/register class table"),
    (0x00423CE7, 1128, "ppcsfp", "tested", "changes extended-asm register-set construction"),
]


PARTITIONS = [
    (0x00422FF4, 0x0042301D, "optional_rpx_tnt_cleanup", "ppc_ep_rpx_tnt", "optional list/instruction cleanup via 0x00422f2e"),
    (0x0042301E, 0x00423059, "eligibility_gates", "useregchgmask + exclusion predicate + proc flag", "decide whether register-change metadata is applicable"),
    (0x0042305A, 0x00423091, "ada_suppression", "ada95 + proc state", "clear existing valid flag and exit for excluded Ada procedures"),
    (0x00423092, 0x00423152, "scan_final_instruction_stream", "none beyond master gates", "zero three masks, preserve old mask subset, walk every finalized instruction; abort on record kind 2"),
    (0x00423153, 0x00423832, "special_register_augmentation", "ajo1==0 && (codefactor || linkxda)", "mark two target register positions; oversized-index paths are std::bitset range-error scaffolding"),
    (0x00423833, 0x0042395F, "commit_register_change_mask", "successful scan", "set valid bit 0x80, clear proc mask, OR shifted working masks and preserved bits into proc+0xb0"),
]


ENCODING_FORMS = [
    (0x00495FC4, "D", "rA@21:5;rB@16:5;imm@0:16", "4", "normal load/store/addi-style D form"),
    (0x00496041, "PSQ_D", "fr@21:5;rA@16:5;disp@0:12;W@15:1;I@12:3", "4", "Gekko/Espresso paired-single quantized D form"),
    (0x004960F6, "PSQ_X", "fr@21:5;rA@16:5;rB@11:5;W@10:1;I@7:3", "4", "Gekko/Espresso paired-single quantized indexed form"),
    (0x004961AB, "I_BRANCH", "disp>>2 packed into 24-bit branch field", "4", "unconditional branch displacement"),
    (0x004961F7, "B_BRANCH", "BO/condition@18:3;disp>>2 into 14-bit branch field", "4", "conditional branch form"),
    (0x00496261, "XL_BRANCH", "field@16:5;value>>2 into 14-bit field", "4", "XL-like target branch form"),
    (0x004962CB, "X", "rD@21:5;rA@16:5;rB@11:5", "4", "three-register X form"),
    (0x00496348, "ROTATE_MASK", "rD@21:5;rA@16:5;sh[0:4]@11:5;sh5@1;mb[0:4]@6:5;mb5@5", "4", "rotate/mask split fields"),
    (0x004964AA, "MULTI5", "f0@21:5;f1@16:5;f2@11:5;f3@6:5;f4@1:5", "4", "five-field PPC form"),
]


# Method slot, target, label, semantics, confidence.
NEARBY_CALLBACKS = [
    (0x5E4, 0x00422FF4, "finalize_register_change_mask", "post-codegen register-change metadata finalizer", "high"),
    (0x5EC, 0x00423CE7, "target_extasm_regset", "construct PPC extended-asm register set", "medium-high"),
    (0x5FC, 0x00424C85, "target_shift_constraint_rewrite", "rewrite shift amount for target constraint 's'", "medium-high"),
    (0x604, 0x00423E2D, "target_extasm_constraint", "handle PPC extended-asm I/U/X constraints", "medium-high"),
    (0x624, 0x00423C13, "target_operand_class", "select operand/register class table for AltiVec/e500", "medium-high"),
    (0x62C, 0x00423AA1, "target_instruction_predicate", "predicate influenced by ppc_isel/ppc_fsel/vectorizer state", "medium-high"),
    (0x634, 0x00424BCE, "target_address_register", "return target address/base register used by assembly operand printer", "medium"),
    (0x64C, 0x00423CAF, "target_small_callback", "small target query adjacent to operand-class callbacks", "medium"),
    (0x674, 0x004242C0, "target_traceback_metadata", "emit PPC64 traceback metadata when Linux PPC64 ABI requests it", "high"),
    (0x67C, 0x005BD98D, "branch_instruction_predicate", "target branch/instruction predicate/filter", "medium-high"),
    (0x684, 0x00424123, "target_state_684", "set target state field to 0x20/0x40 from target mode", "medium"),
    (0x7AC, 0x004244C6, "target_relocatable_ir_lowering", "rewrite relocatable/symbolic PPC IR before binary/text emission", "high"),
    (0x7B4, 0x0049A873, "target_relocation_adjust", "adjust PPC relocation field offset/width/type before generic relocation creation", "high"),
]


ESPRESSO_OPTIONS = [4649, 4658, 4711, 4712, 4713, 4714, 4715, 4725, 4726, 4727, 4728, 4729, 4997]

ORACLE_RELOCATION_FIXTURES = [
    "analysis/oracle/fingerprint_repeat_a/branch__speed/backend.o",
    "analysis/oracle/fingerprint_repeat_b/loop__debug/probe.o",
]


def hx(value: int) -> str:
    return f"0x{value:08x}"


def read_c_string(blob: bytes, va: int) -> str:
    # For this image .rdata/.data raw offsets equal VA-image_base.
    off = va - 0x00400000
    if not (0 <= off < len(blob)):
        raise ValueError(f"VA outside raw image: {va:#x}")
    end = blob.find(b"\0", off)
    if end < 0:
        raise ValueError(f"unterminated string at {va:#x}")
    return blob[off:end].decode("ascii", errors="replace")


def load_inventory() -> dict[int, dict[str, str]]:
    rows: dict[int, dict[str, str]] = {}
    with (ROOT / "analysis/ghidra/out/inventory/functions.tsv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            rows[int(row["entry"], 16)] = row
    return rows


def load_options() -> tuple[dict[int, str], dict[int, tuple[int, str]]]:
    by_id: dict[int, str] = {}
    by_addr: dict[int, tuple[int, str]] = {}
    with (ROOT / "analysis/manual/internal_option_ids.tsv").open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            option_id = int(row["id"])
            name = row["name"]
            by_id[option_id] = name
            by_addr[OPTION_BASE + option_id] = (option_id, name)
    return by_id, by_addr


def write_function_map(inventory: dict[int, dict[str, str]]) -> None:
    # Keep this compact core table separate from the richer AI-ingestion
    # function_map.csv produced by build_ai_manifest.py.
    with (OUT / "core_function_map.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["entry", "end", "size", "ghidra_name", "analysis_name", "role", "confidence", "evidence"])
        for address, label, role, confidence, evidence in FUNCTIONS:
            row = inventory[address]
            w.writerow([hx(address), "0x" + row["body_max"].lower(), row["body_size"], row["name"], label, role, confidence, evidence])


def write_option_gates(options: dict[int, str]) -> None:
    with (OUT / "option_gates.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["function", "option_id", "option_name", "option_byte_va", "condition", "effect"])
        for function, option_id, expected_name, condition, effect in OPTION_GATES:
            actual = options.get(option_id)
            if actual != expected_name:
                raise SystemExit(f"option ID {option_id}: expected {expected_name!r}, got {actual!r}")
            w.writerow([hx(function), option_id, expected_name, hx(OPTION_BASE + option_id), condition, effect])


def write_partitions() -> None:
    with (OUT / "finalizer_partitions.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["start", "end", "partition", "gate", "semantics"])
        for start, end, name, gate, semantics in PARTITIONS:
            w.writerow([hx(start), hx(end), name, gate, semantics])


def write_encoding_forms() -> None:
    with (OUT / "encoding_forms.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["function", "form", "packed_fields", "output_bytes", "notes"])
        for row in ENCODING_FORMS:
            w.writerow([hx(row[0]), *row[1:]])


def write_nearby_callbacks() -> None:
    vtable_path = ROOT / "analysis/backend_map/target_vtable.csv"
    table: dict[int, int] = {}
    with vtable_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            table[int(row["method_offset"], 16)] = int(row["target_va"], 16)
    with (OUT / "nearby_target_callbacks.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["method_offset", "target_va", "analysis_name", "semantics", "confidence"])
        for slot, target, label, semantics, confidence in NEARBY_CALLBACKS:
            actual = table.get(slot)
            if actual != target:
                raise SystemExit(f"target-vtable slot {slot:#x}: expected {target:#x}, got {actual!r}")
            w.writerow([f"0x{slot:x}", hx(target), label, semantics, confidence])


def write_espresso_option_xrefs(blob: bytes, inventory: dict[int, dict[str, str]], options: dict[int, str]) -> int:
    """Find the compiler's common `mov OPTION_BASE; add option_id` reference form.

    This is intentionally named a pattern-xref table: zero rows for an option do
    not prove that the option is unused because some initialization/configuration
    code addresses option bytes through tables or other instruction sequences.
    """
    ranges = sorted(
        (int(row["body_min"], 16), int(row["body_max"], 16), va, row["name"])
        for va, row in inventory.items()
    )
    starts = [row[0] for row in ranges]
    rows: list[list[object]] = []
    text_start, text_end = 0x1000, 0x6B7000
    for option_id in ESPRESSO_OPTIONS:
        pattern = b"\xb8\x4e\x06\xc4\x00\x05" + option_id.to_bytes(4, "little")
        cursor = text_start
        while True:
            offset = blob.find(pattern, cursor, text_end)
            if offset < 0:
                break
            va = 0x00400000 + offset
            index = bisect.bisect_right(starts, va) - 1
            function_entry = ""
            function_name = ""
            if index >= 0:
                low, high, entry, raw_name = ranges[index]
                if low <= va <= high:
                    function_entry = hx(entry)
                    function_name = raw_name
            rows.append([
                option_id,
                options.get(option_id, ""),
                hx(OPTION_BASE + option_id),
                hx(va),
                function_entry,
                function_name,
                "mov_option_base_add_id",
            ])
            cursor = offset + 1
    with (OUT / "espresso_option_xrefs.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["option_id", "option_name", "option_byte_va", "reference_va", "function_entry", "function_name", "xref_pattern"])
        w.writerows(rows)
    return len(rows)


def write_relocation_evidence() -> int:
    rows: dict[tuple[int, str], set[str]] = {}
    rx = re.compile(r"^\s*[0-9a-f]+\s+([0-9a-f]+)\s+(R_PPC_[A-Z0-9_]+)\b", re.I)
    for relative in ORACLE_RELOCATION_FIXTURES:
        path = ROOT / relative
        output = subprocess.check_output(["readelf", "-r", str(path)], text=True)
        for line in output.splitlines():
            match = rx.match(line)
            if not match:
                continue
            info = int(match.group(1), 16)
            reloc_id = info & 0xFF
            name = match.group(2)
            rows.setdefault((reloc_id, name), set()).add(relative)
    encoder = {
        10: "0x00497b18 emits relocation 10 before 0x004961ab I-form branch encoding",
        11: "0x00497b18 emits relocation 11 before 0x004961f7 B-form conditional branch encoding",
    }
    with (OUT / "relocation_map.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["relocation_id", "elf_name", "oracle_fixtures", "encoder_evidence"])
        for (reloc_id, name), fixtures in sorted(rows.items()):
            w.writerow([reloc_id, name, ";".join(sorted(fixtures)), encoder.get(reloc_id, "oracle ELF evidence")])
    return len(rows)


def write_finalizer_direct_calls(inventory: dict[int, dict[str, str]]) -> int:
    output = subprocess.check_output(
        [
            "objdump", "-d", "-Mintel", "--start-address=0x00422ff4",
            "--stop-address=0x00423965", str(BIN),
        ],
        text=True,
    )
    groups = {
        0x00422F2E: "rpx_tnt_cleanup",
        0x004E427D: "eligibility_predicate",
        0x00406399: "bitset_core",
        0x004059D8: "bitset_core",
        0x00405D8A: "bitset_core",
        0x00408B78: "instruction_walker",
        0x00405DF8: "bitset_core",
        0x00405DC1: "bitset_core",
        0x00A94070: "range_error_scaffolding",
        0x00A93990: "range_error_scaffolding",
        0x00A9214F: "range_error_scaffolding",
        0x00A9252B: "range_error_scaffolding",
        0x00A91F74: "range_error_scaffolding",
        0x0040581D: "range_error_scaffolding",
        0x0040527B: "range_error_scaffolding",
        0x004056DC: "range_error_scaffolding",
        0x00405200: "range_error_scaffolding",
        0x0040578F: "range_error_scaffolding",
    }
    rx = re.compile(r"^\s*([0-9a-f]+):.*\bcall\s+0x([0-9a-f]+)", re.I)
    rows: list[tuple[int, int, str, str]] = []
    for line in output.splitlines():
        match = rx.match(line)
        if not match:
            continue
        site = int(match.group(1), 16)
        target = int(match.group(2), 16)
        name = inventory.get(target, {}).get("name", "")
        rows.append((site, target, name, groups.get(target, "support")))
    with (OUT / "finalizer_direct_calls.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["callsite", "target", "ghidra_name", "semantic_group"])
        for site, target, name, group in rows:
            w.writerow([hx(site), hx(target), name, group])
    return len({target for _, target, _, _ in rows})


def parse_opcode_table(blob: bytes) -> list[dict[str, object]]:
    path = OUT / "decompiled/00491eb5_ppc_opcode_table_init.c"
    text = path.read_text(encoding="utf-8")
    pattern = re.compile(r"FUN_00491dc0\((.+?),\s*(0x[0-9a-f]+|\d+),\s*(0x[0-9a-f]+|\d+)\);", re.I)
    rows: list[dict[str, object]] = []
    for index, match in enumerate(pattern.finditer(text)):
        arg, format_id_s, base_s = match.groups()
        addr_match = re.search(r"_00([0-9a-f]{6})\b", arg, re.I)
        if not addr_match:
            raise SystemExit(f"cannot recover mnemonic address from {arg!r}")
        string_va = int(addr_match.group(1), 16)
        mnemonic = read_c_string(blob, string_va)
        if mnemonic.startswith(("ps_", "psq_")):
            category = "paired_single"
        elif mnemonic.startswith(("b", "bc")):
            category = "branch_or_branch_alias"
        elif mnemonic.startswith(("v", "lv", "stv")):
            category = "altivec_or_vector"
        else:
            category = "base_ppc"
        rows.append({
            "index": index,
            "mnemonic": mnemonic,
            "string_va": string_va,
            "format_id": int(format_id_s, 0),
            "base_encoding": int(base_s, 0) & 0xFFFFFFFF,
            "category": category,
        })
    if len(rows) != 572:
        raise SystemExit(f"expected 572 opcode registrations, found {len(rows)}")
    with (OUT / "opcode_table.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["index", "mnemonic", "string_va", "format_id", "base_encoding", "category"])
        for row in rows:
            w.writerow([row["index"], row["mnemonic"], hx(row["string_va"]), row["format_id"], f"0x{row['base_encoding']:08x}", row["category"]])
    return rows


def write_target_defaults(option_by_addr: dict[int, tuple[int, str]]) -> int:
    text = (OUT / "decompiled/00476da3_ppc_target_option_and_opcode_init.c").read_text(encoding="utf-8")
    found: dict[int, int] = {}
    for match in re.finditer(r"DAT_00(c4[0-9a-f]{4})\s*=\s*([01]);", text, re.I):
        address = int(match.group(1), 16)
        if address in option_by_addr:
            found[address] = int(match.group(2))
    with (OUT / "target_default_options.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["option_id", "option_name", "option_byte_va", "default_value", "target_relevance"])
        count = 0
        for address in sorted(found):
            option_id, name = option_by_addr[address]
            lower = name.lower()
            relevant = (
                lower.startswith("ppc") or lower.startswith("espresso") or
                name in {"AltiVec", "AltiVec_VRSAVE", "ghsasm", "graph_allocate", "dwarf_no_frame_sec", "bigendian"}
            )
            if not relevant:
                continue
            w.writerow([option_id, name, hx(address), found[address], "ppc_or_wiiu_target_default"])
            count += 1
    return count


def parse_objdump_words(path: Path) -> list[tuple[int, int, str]]:
    try:
        output = subprocess.check_output(
            ["llvm-objdump", "-d", "--triple=powerpc-unknown-linux-gnu", str(path)],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    rows = []
    rx = re.compile(r"^\s*([0-9a-f]+):\s+([0-9a-f]{2})\s+([0-9a-f]{2})\s+([0-9a-f]{2})\s+([0-9a-f]{2})\s+([A-Za-z0-9_.]+)", re.I)
    for line in output.splitlines():
        m = rx.match(line)
        if not m:
            continue
        off = int(m.group(1), 16)
        word = int("".join(m.group(i) for i in range(2, 6)), 16)
        mnemonic = m.group(6)
        rows.append((off, word, mnemonic))
    return rows


def write_oracle_correlation(opcodes: list[dict[str, object]]) -> int:
    lookup = {str(row["mnemonic"]): row for row in opcodes}
    fixture = ROOT / "analysis/oracle/fingerprint_new_smoke/paired_candidate__general/probe.o"
    observed = parse_objdump_words(fixture)
    wanted = {"addi", "lfsx", "stfsx", "fmadds", "blr"}
    rows: list[list[object]] = []
    seen: set[str] = set()
    for offset, word, mnemonic in observed:
        if mnemonic not in wanted or mnemonic in seen or mnemonic not in lookup:
            continue
        seen.add(mnemonic)
        op = lookup[mnemonic]
        rows.append([
            str(fixture.relative_to(ROOT)), "ELF32-big object", mnemonic, f"0x{offset:08x}",
            f"0x{word:08x}", f"0x{int(op['base_encoding']):08x}", op["format_id"],
            "oracle object word produced by GHS 5.3.22 Nintendo",
        ])
    ps = lookup["ps_merge10"]
    rows.append([
        "analysis/oracle/_ps_probe/ps.s", "text assembly", "ps_merge10", "", "",
        f"0x{int(ps['base_encoding']):08x}", ps["format_id"],
        "oracle -S output names this paired-single instruction; registry supplies its base word",
    ])
    with (OUT / "oracle_correlation.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["fixture", "output_kind", "mnemonic", "text_offset", "observed_word", "registry_base_encoding", "format_id", "evidence"])
        w.writerows(rows)
    return len(rows)


def main() -> None:
    blob = BIN.read_bytes()
    sha = hashlib.sha256(blob).hexdigest()
    if sha != EXPECTED_SHA256:
        raise SystemExit(f"unexpected ecomppc.exe SHA-256: {sha}")
    inventory = load_inventory()
    options, option_by_addr = load_options()
    for address, *_ in FUNCTIONS:
        if address not in inventory:
            raise SystemExit(f"missing Ghidra function boundary for {address:#x}")
    write_function_map(inventory)
    write_option_gates(options)
    write_partitions()
    write_encoding_forms()
    write_nearby_callbacks()
    espresso_xref_count = write_espresso_option_xrefs(blob, inventory, options)
    finalizer_direct_callees = write_finalizer_direct_calls(inventory)
    opcodes = parse_opcode_table(blob)
    default_count = write_target_defaults(option_by_addr)
    oracle_count = write_oracle_correlation(opcodes)
    relocation_count = write_relocation_evidence()
    paired = sum(1 for row in opcodes if row["category"] == "paired_single")
    summary = {
        "target": {"path": str(BIN.relative_to(ROOT)), "sha256": sha},
        "vtable_seam": {"slot": "0x5e4", "target": "0x00422ff4", "recovered_semantics": "register-change-mask finalizer"},
        "output_boundary": {"dispatcher": "0x0047f1a6", "option": "obj", "option_id": 75, "option_byte_va": "0x00c40699", "text_when": 0, "binary_when": "nonzero", "binary_encoder": "0x00497b18", "text_operand_printer": "0x0047e00e"},
        "opcode_registry": {"initializer": "0x00491eb5", "inserter": "0x00491dc0", "hash_buckets": 255, "entry_count": len(opcodes), "paired_single_entries": paired},
        "register_mask": {"width_bits": 96, "word_count": 6, "working_masks": ["0x00bdb560", "0x00bdb56c", "0x00bdb578"], "destination": "target-proc-state + 0xb0", "valid_flag": "target-proc-state + 0x59 bit 0x80"},
        "counts": {"functions": len(FUNCTIONS), "option_gates": len(OPTION_GATES), "partitions": len(PARTITIONS), "encoding_forms": len(ENCODING_FORMS), "nearby_target_callbacks": len(NEARBY_CALLBACKS), "finalizer_unique_direct_callees": finalizer_direct_callees, "target_default_options": default_count, "espresso_pattern_xrefs": espresso_xref_count, "oracle_correlations": oracle_count, "oracle_relocation_types": relocation_count},
    }
    (OUT / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"wrote emitter map: {len(FUNCTIONS)} functions, {len(opcodes)} opcodes ({paired} paired-single), {default_count} PPC/WiiU defaults, {oracle_count} oracle correlations")


if __name__ == "__main__":
    main()
