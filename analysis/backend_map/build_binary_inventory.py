#!/usr/bin/env python3
"""Build compact machine-readable PE/type metadata for ecomppc.exe.

The source data is the local static-anchor extraction and Ghidra function
inventory.  Output contains addresses and metadata only; no executable bytes or
decompiler text are copied.
"""

from __future__ import annotations

import csv
import json
import re
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
ANCHORS = ROOT / "analysis/manual/ecomppc_static_anchors.json"
FUNCTIONS = ROOT / "analysis/ghidra/out/inventory/functions.tsv"
OPTION_IDS = ROOT / "analysis/manual/internal_option_ids.tsv"
OPTION_BASE = 0x00C4064E
TARGET_OPTION_RE = re.compile(
    r"^(?:espresso|ppc|powerpc|altivec|vrsave|sda|zda|toc)", re.IGNORECASE
)


def hx(value: int) -> str:
    return f"0x{value:08x}"


def load_function_summary() -> dict[str, object]:
    by_source: Counter[str] = Counter()
    total = 0
    thunks = 0
    with FUNCTIONS.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f, delimiter="\t"):
            total += 1
            by_source[row["source"]] += 1
            if row["thunk"].lower() == "true":
                thunks += 1
    return {
        "recognized_functions": total,
        "by_symbol_source": dict(sorted(by_source.items())),
        "thunks": thunks,
        "source": "analysis/ghidra/out/inventory/functions.tsv",
    }


def build_inventory(anchors: dict[str, object]) -> dict[str, object]:
    imports = []
    total_imports = 0
    for dll in anchors["imports"]:
        count = len(dll["symbols"])
        total_imports += count
        imports.append(
            {
                "dll": dll["dll"],
                "iat_va": hx(dll["iat_va"]),
                "symbol_count": count,
                "named_symbols": [
                    symbol["name"] for symbol in dll["symbols"] if "name" in symbol
                ],
                "ordinal_only_count": sum(
                    1 for symbol in dll["symbols"] if "ordinal" in symbol
                ),
            }
        )

    rtti = []
    for item in anchors["msvc_rtti"]:
        rtti.append(
            {
                "name": item["name"],
                "type_descriptor_va": hx(item["type_descriptor_va"]),
                "objects": [
                    {
                        "complete_object_locator_va": hx(
                            obj["complete_object_locator_va"]
                        ),
                        "vftable_va": hx(obj["vftable_va"]),
                        "entries": [
                            {"va": hx(entry["va"]), "function": entry["function"]}
                            for entry in obj["entries"]
                        ],
                    }
                    for obj in item["objects"]
                ],
            }
        )

    return {
        "target": {
            "path": anchors["file"],
            "sha256": anchors["sha256"],
            "size": anchors["size"],
            "pe_timestamp": anchors["timestamp"],
            "image_base": hx(anchors["image_base"]),
            "entry_rva": hx(anchors["entry_rva"]),
            "entry_va": hx(anchors["entry_va"]),
            "size_of_image": hx(anchors["size_of_image"]),
        },
        "sections": [
            {
                "name": section["name"],
                "rva": hx(section["rva"]),
                "va": hx(section["va"]),
                "virtual_size": hx(section["virtual_size"]),
                "raw_offset": hx(section["raw_offset"]),
                "raw_size": hx(section["raw_size"]),
                "characteristics": hx(section["characteristics"]),
            }
            for section in anchors["sections"]
        ],
        "imports": {
            "dll_count": len(imports),
            "symbol_count": total_imports,
            "dlls": imports,
        },
        "function_recovery": load_function_summary(),
        "msvc_rtti": rtti,
        "compiler_named_registry_count": len(anchors["named_registries"]),
        "source": "analysis/manual/ecomppc_static_anchors.json",
    }


def write_registry_csv(anchors: dict[str, object]) -> None:
    path = OUT / "class_registry.csv"
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "string_va", "registration_refs", "kind"])
        for item in anchors["named_registries"]:
            refs = ";".join(hx(addr) for addr in item["pointer_refs"])
            writer.writerow(
                [
                    item["name"],
                    hx(item["string_va"]),
                    refs,
                    "compiler_internal_registration",
                ]
            )


def write_target_options_csv() -> int:
    path = OUT / "target_options.csv"
    count = 0
    with OPTION_IDS.open(newline="", encoding="utf-8") as source, path.open(
        "w", newline="", encoding="utf-8"
    ) as output:
        reader = csv.DictReader(source, delimiter="\t")
        writer = csv.writer(output)
        writer.writerow(
            [
                "option_id",
                "option_name",
                "option_byte_va",
                "option_table_file_offset",
                "name_va",
            ]
        )
        for row in reader:
            if not TARGET_OPTION_RE.search(row["name"]):
                continue
            option_id = int(row["id"])
            writer.writerow(
                [
                    option_id,
                    row["name"],
                    hx(OPTION_BASE + option_id),
                    row["table_file_offset"],
                    row["string_va"],
                ]
            )
            count += 1
    return count


def main() -> None:
    anchors = json.loads(ANCHORS.read_text(encoding="utf-8"))
    inventory = build_inventory(anchors)
    (OUT / "binary_inventory.json").write_text(
        json.dumps(inventory, indent=2) + "\n", encoding="utf-8"
    )
    write_registry_csv(anchors)
    target_option_count = write_target_options_csv()
    print(
        "wrote binary_inventory.json, class_registry.csv, and target_options.csv "
        f"({inventory['imports']['symbol_count']} imports, "
        f"{inventory['function_recovery']['recognized_functions']} functions, "
        f"{target_option_count} target options)"
    )


if __name__ == "__main__":
    main()
