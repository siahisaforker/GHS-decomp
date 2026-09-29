#!/usr/bin/env python3
"""Validate deterministic AI-ingestion invariants for auto_names outputs."""

from __future__ import annotations

import csv
import json
import re
from pathlib import Path


HERE = Path(__file__).resolve().parent
VA = re.compile(r"0x[0-9a-f]{8}$")


def fail(message: str) -> None:
    raise SystemExit(message)


def main() -> int:
    summary = json.loads((HERE / "summary.json").read_text())
    checkpoint = json.loads((HERE / "checkpoint.json").read_text())

    with (HERE / "proposals.tsv").open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f, delimiter="\t"))
    if len(rows) != summary["proposal_count"]:
        fail(f"proposal count mismatch: tsv={len(rows)} summary={summary['proposal_count']}")
    if len({r["va"] for r in rows}) != len(rows):
        fail("duplicate proposal VA")
    if len({r["proposed_name"] for r in rows}) != len(rows):
        fail("duplicate proposed_name")

    last_key = None
    for i, r in enumerate(rows, start=2):
        if r["record_type"] != "naming_hypothesis":
            fail(f"line {i}: wrong record_type")
        if not VA.fullmatch(r["va"]):
            fail(f"line {i}: invalid VA {r['va']!r}")
        conf = float(r["confidence"])
        if not 0.0 <= conf <= 1.0:
            fail(f"line {i}: confidence out of range")
        if not r["raw_name"] or not r["proposed_name"]:
            fail(f"line {i}: missing raw/proposed name")
        if not r["evidence_kinds"] or not r["evidence_refs"]:
            fail(f"line {i}: missing evidence")
        if not r["provenance"] or not r["provenance_sources"]:
            fail(f"line {i}: missing provenance")
        key = (-conf, int(r["va"], 16))
        if last_key is not None and key < last_key:
            fail(f"line {i}: nondeterministic ordering")
        last_key = key

    obs_count = 0
    with (HERE / "observations.jsonl").open(encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            r = json.loads(line)
            obs_count += 1
            if r.get("record_type") != "observed_function":
                fail(f"observations line {i}: wrong record_type")
            if not VA.fullmatch(r.get("va", "")):
                fail(f"observations line {i}: invalid VA")
    if obs_count != summary["functions_total"]:
        fail(f"observation count mismatch: {obs_count} != {summary['functions_total']}")

    jsonl_count = 0
    with (HERE / "proposals.jsonl").open(encoding="utf-8") as f:
        for i, line in enumerate(f, start=1):
            r = json.loads(line)
            jsonl_count += 1
            if r.get("record_type") != "naming_hypothesis":
                fail(f"proposals jsonl line {i}: wrong record_type")
    if jsonl_count != len(rows):
        fail(f"jsonl/tsv proposal mismatch: {jsonl_count} != {len(rows)}")

    if checkpoint.get("resume_command") != "python3 analysis/auto_names/build_auto_names.py":
        fail("checkpoint resume command missing or changed")
    print(json.dumps({"status": "ok", "observations": obs_count, "proposals": len(rows)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
