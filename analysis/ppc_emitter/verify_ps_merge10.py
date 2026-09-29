#!/usr/bin/env python3
"""Byte-level oracle check for the recovered Espresso paired-single encoder.

Compiles the existing ps.c fixture with the local GHS package into /tmp,
derives the expected ps_merge10 word from opcode_table.csv plus the operands in
the generated reference assembly, and verifies that exact big-endian word is
present in the resulting ELF .text section.
"""

from __future__ import annotations

import csv
import json
import os
import re
import struct
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
COMPILER = ROOT / "ghs5.3.22/bin/cxppc.exe"
SOURCE = ROOT / "analysis/oracle/_ps_probe/ps.c"
ASM = ROOT / "analysis/oracle/_ps_probe/ps.s"
OPCODES = OUT / "opcode_table.csv"
RESULT = OUT / "oracle_ps_merge10_validation.json"


def opcode_row(name: str) -> dict[str, str]:
    with OPCODES.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["mnemonic"] == name:
                return row
    raise SystemExit(f"opcode {name!r} is missing from {OPCODES}")


def ps_merge10_operands() -> tuple[int, int, int]:
    match = re.search(
        r"^\s*ps_merge10\s+f(\d+)\s*,\s*f(\d+)\s*,\s*f(\d+)\s*$",
        ASM.read_text(encoding="utf-8", errors="replace"),
        re.MULTILINE,
    )
    if not match:
        raise SystemExit(f"ps_merge10 fixture line not found in {ASM}")
    regs = tuple(int(value) for value in match.groups())
    if any(reg > 31 for reg in regs):
        raise SystemExit(f"unexpected paired-single register operands: {regs}")
    return regs


def elf_text(blob: bytes) -> tuple[int, bytes]:
    if blob[:4] != b"\x7fELF" or blob[4] != 1 or blob[5] != 2:
        raise SystemExit("oracle output is not big-endian ELF32")
    e_shoff = struct.unpack_from(">I", blob, 0x20)[0]
    e_shentsize = struct.unpack_from(">H", blob, 0x2E)[0]
    e_shnum = struct.unpack_from(">H", blob, 0x30)[0]
    e_shstrndx = struct.unpack_from(">H", blob, 0x32)[0]
    shstr = e_shoff + e_shstrndx * e_shentsize
    shstr_off = struct.unpack_from(">I", blob, shstr + 0x10)[0]
    shstr_size = struct.unpack_from(">I", blob, shstr + 0x14)[0]
    names = blob[shstr_off : shstr_off + shstr_size]
    for index in range(e_shnum):
        sh = e_shoff + index * e_shentsize
        name_off = struct.unpack_from(">I", blob, sh)[0]
        end = names.find(b"\0", name_off)
        name = names[name_off:end].decode("ascii", errors="replace")
        if name == ".text":
            offset = struct.unpack_from(">I", blob, sh + 0x10)[0]
            size = struct.unpack_from(">I", blob, sh + 0x14)[0]
            return offset, blob[offset : offset + size]
    raise SystemExit("oracle object has no .text section")


def main() -> None:
    descriptor = opcode_row("ps_merge10")
    base = int(descriptor["base_encoding"], 16)
    rd, ra, rb = ps_merge10_operands()
    expected = (base | (rd << 21) | (ra << 16) | (rb << 11)) & 0xFFFFFFFF

    fd, tmp_name = tempfile.mkstemp(prefix="ghs_ps_merge10_", suffix=".o", dir="/tmp")
    os.close(fd)
    tmp = Path(tmp_name)
    tmp.unlink()
    wine_output = "Z:\\tmp\\" + tmp.name
    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"
    command = [
        "wine",
        str(COMPILER.relative_to(ROOT)),
        "-O2",
        "-c",
        "-o",
        wine_output,
        str(SOURCE.relative_to(ROOT)),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if completed.returncode != 0 or not tmp.exists():
            raise SystemExit(
                "oracle compile failed\n"
                f"returncode={completed.returncode}\n"
                f"stdout={completed.stdout}\n"
                f"stderr={completed.stderr}"
            )
        blob = tmp.read_bytes()
        text_file_offset, text = elf_text(blob)
        needle = expected.to_bytes(4, "big")
        text_offset = text.find(needle)
        if text_offset < 0:
            raise SystemExit(
                f"expected ps_merge10 word 0x{expected:08x} not found in oracle .text"
            )
        result = {
            "fixture": str(SOURCE.relative_to(ROOT)),
            "reference_assembly": str(ASM.relative_to(ROOT)),
            "compiler": "C-POWERPC 5.3.22 RELEASE VERSION / MULTI v5.3.22 Nintendo",
            "mnemonic": "ps_merge10",
            "operands": [f"f{rd}", f"f{ra}", f"f{rb}"],
            "format_id": int(descriptor["format_id"]),
            "registry_base_encoding": f"0x{base:08x}",
            "field_formula": "base | (frD << 21) | (frA << 16) | (frB << 11)",
            "expected_word": f"0x{expected:08x}",
            "observed_word": f"0x{int.from_bytes(text[text_offset:text_offset + 4], 'big'):08x}",
            "text_section_offset": f"0x{text_offset:x}",
            "elf_text_file_offset": f"0x{text_file_offset:x}",
            "matched": True,
        }
        RESULT.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(
            f"verified ps_merge10: 0x{expected:08x} at .text+0x{text_offset:x}; "
            f"wrote {RESULT.relative_to(ROOT)}"
        )
    finally:
        tmp.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
