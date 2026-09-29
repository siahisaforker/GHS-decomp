#!/usr/bin/env python3
"""Run generated full-decomp batch lists through Ghidra headless decompiler."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
HEADLESS = ROOT / "tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless"
PROJECT_DIR = ROOT / "analysis/ghidra/project"
SCRIPT_DIR = ROOT / "analysis/ghidra/scripts"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--wave", action="append", help="restrict to one or more waves")
    ap.add_argument("--batch", action="append", help="restrict to batch id(s)")
    ap.add_argument("--limit", type=int, help="run at most this many matching batches")
    ap.add_argument("--out", type=Path, default=HERE / "exports")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--coalesce", action="store_true", help="combine selected batches into one headless run")
    args = ap.parse_args()

    batches = json.loads((HERE / "batches.json").read_text(encoding="utf-8"))
    selected = []
    for b in batches:
        if args.wave and b["wave"] not in args.wave:
            continue
        if args.batch and b["id"] not in args.batch:
            continue
        selected.append(b)
    if args.limit is not None:
        selected = selected[:args.limit]

    args.out.mkdir(parents=True, exist_ok=True)
    if args.coalesce and selected:
        membership = []
        lines = []
        seen = set()
        for b in selected:
            for line in (HERE / b["list"]).read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                va = line.split("\t", 1)[0].lower()
                if va in seen:
                    continue
                seen.add(va)
                lines.append(line)
                membership.append({"va": "0x" + va, "batch_id": b["id"], "wave": b["wave"], "module": b["module"]})
        coalesced_list = args.out / "coalesced_input.tsv"
        coalesced_list.write_text("\n".join(lines) + "\n", encoding="utf-8")
        out_dir = args.out / "coalesced"
        cmd = [
            str(HEADLESS), str(PROJECT_DIR), "GHS5322",
            "-process", "ecomppc.exe", "-readOnly", "-noanalysis",
            "-scriptPath", str(SCRIPT_DIR),
            "-postScript", "DecompileAddresses.java", str(coalesced_list), str(out_dir),
        ]
        print(" ".join(cmd))
        if args.dry_run:
            return 0
        p = subprocess.run(cmd, cwd=ROOT)
        written = len(list(out_dir.glob("*.c"))) if out_dir.is_dir() else 0
        receipt = {
            "schema_version": 1,
            "provenance": "analysis/full_decomp/export_batches.py",
            "mode": "coalesced",
            "requested_functions": len(lines),
            "written_functions": written,
            "returncode": p.returncode,
            "selected_batches": [b["id"] for b in selected],
            "selected_waves": sorted({b["wave"] for b in selected}),
            "membership": membership,
        }
        (args.out / "export_receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
        return p.returncode if p.returncode else (0 if written == len(lines) else 2)

    failures = 0
    for b in selected:
        list_path = HERE / b["list"]
        out_dir = args.out / b["id"]
        cmd = [
            str(HEADLESS), str(PROJECT_DIR), "GHS5322",
            "-process", "ecomppc.exe", "-readOnly", "-noanalysis",
            "-scriptPath", str(SCRIPT_DIR),
            "-postScript", "DecompileAddresses.java", str(list_path), str(out_dir),
        ]
        print(" ".join(cmd))
        if args.dry_run:
            continue
        p = subprocess.run(cmd, cwd=ROOT)
        if p.returncode:
            failures += 1
            print(f"FAILED {b['id']}: rc={p.returncode}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
