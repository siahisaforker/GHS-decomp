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
    failures = 0
    for b in selected:
        list_path = HERE / b["list"]
        out_dir = args.out / b["id"]
        cmd = [
            str(HEADLESS), str(PROJECT_DIR), "GHS5322",
            "-process", "ecomppc.exe", "-noanalysis",
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
