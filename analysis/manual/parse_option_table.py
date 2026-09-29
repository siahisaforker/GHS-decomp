#!/usr/bin/env python3
from pathlib import Path
import re
import struct
from collections import defaultdict

ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "ghs5.3.22" / "bin" / "ecomppc.exe"

# PE sections: (virtual address, file offset, size)
SECTIONS = [
    (0x00401000, 0x00001000, 0x006B5934),
    (0x00AB7000, 0x006B7000, 0x00007A96),
    (0x00ABF000, 0x006BF000, 0x00118000),
    (0x00D4B000, 0x007D7000, 0x0000013C),
]


def va_to_file(va):
    for base, off, size in SECTIONS:
        if base <= va < base + size:
            return off + (va - base)
    return None


def read_ascii(blob, va):
    off = va_to_file(va)
    if off is None:
        return None
    end = blob.find(b"\0", off, min(off + 160, len(blob)))
    if end <= off:
        return None
    raw = blob[off:end]
    if len(raw) > 100 or not all(32 <= c < 127 for c in raw):
        return None
    return raw.decode("ascii")


def main():
    blob = BINARY.read_bytes()
    rows = []
    # Large table found in .data: numeric internal option key + string pointer.
    for off in range(0x006F23D0, 0x006FAB38, 8):
        option_id, string_va = struct.unpack_from("<II", blob, off)
        name = read_ascii(blob, string_va)
        if 0 < option_id < 10000 and name:
            rows.append((option_id, name, off, string_va))

    out = ROOT / "analysis" / "manual" / "internal_option_ids.tsv"
    out.write_text(
        "id\tname\ttable_file_offset\tstring_va\n"
        + "\n".join(
            f"{option_id}\t{name}\t0x{off:x}\t0x{string_va:x}"
            for option_id, name, off, string_va in rows
        )
        + "\n"
    )

    names = defaultdict(list)
    for option_id, name, _, _ in rows:
        if name not in names[option_id]:
            names[option_id].append(name)

    driver = (ROOT / "analysis" / "driver" / "Ogeneral.txt").read_text()
    used = []
    for match in re.finditer(r"-(?:X|Z)(\d+)", driver):
        option_id = int(match.group(1))
        if option_id not in used:
            used.append(option_id)

    print(f"mapped entries: {len(rows)}")
    print(f"unique numeric ids: {len(names)}")
    print("\nInternal switches emitted by the Wii U driver:")
    for option_id in used:
        print(f"{option_id:4d}: {', '.join(names.get(option_id, ['?']))}")


if __name__ == "__main__":
    main()
