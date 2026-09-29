#!/usr/bin/env python3
"""Run the richer fingerprint corpus using probe_ghs.py and diff its modes."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
from pathlib import Path
import sys

import probe_ghs as oracle

HERE = Path(__file__).resolve().parent
CORPUS = HERE / "corpus"
DEFAULT_OUT = HERE / "fingerprint_runs"
MODE_ORDER = ["maxdebug", "debug", "general", "speed", "space"]


def sha_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_manifest() -> list[dict]:
    return json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--modes", nargs="+", choices=MODE_ORDER, default=MODE_ORDER)
    ap.add_argument("--probes", nargs="*", help="names from corpus/manifest.json")
    ap.add_argument("--extra", action="append", default=[], help="extra cxppc flag")
    args = ap.parse_args()

    manifest = load_manifest()
    known = {entry["name"] for entry in manifest}
    if args.probes:
        unknown = sorted(set(args.probes) - known)
        if unknown:
            ap.error("unknown probes: " + ", ".join(unknown))
        manifest = [entry for entry in manifest if entry["name"] in args.probes]

    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    matrix = []
    failures = 0

    for entry in manifest:
        source_path = CORPUS / entry["file"]
        source = source_path.read_text(encoding="utf-8")
        suffix = source_path.suffix
        for mode in args.modes:
            rc, meta = oracle.compile_one(
                entry["name"], source, suffix, mode, args.extra, out
            )
            failures += 1 if rc else 0
            run_dir = out / f"{entry['name']}__{mode}"
            normalized = run_dir / "probe.normalized.s"
            record = {
                "probe": entry["name"],
                "language": entry["language"],
                "mode": mode,
                "returncode": rc,
                "normalized_asm_sha256": (
                    hashlib.sha256(normalized.read_bytes()).hexdigest()
                    if normalized.is_file() else None
                ),
                "object_sha256": meta.get("sha256", {}).get("object") if not rc else None,
                "text_sha256": meta.get("sha256", {}).get("text") if not rc else None,
                "backend_normalized_asm_sha256": meta.get("sha256", {}).get("backend_assembly_normalized") if not rc else None,
                "backend_text_sha256": meta.get("sha256", {}).get("backend_text") if not rc else None,
            }
            matrix.append(record)
            print(f"[{'ok' if rc == 0 else 'FAIL'}] {entry['name']}/{mode}")

    fingerprints: dict[str, dict[str, dict]] = {}
    for entry in manifest:
        name = entry["name"]
        fingerprints[name] = {}
        for mode in args.modes:
            run_dir = out / f"{name}__{mode}"
            normalized = run_dir / "probe.normalized.s"
            if not normalized.is_file():
                continue
            text = normalized.read_text(encoding="utf-8", errors="replace")
            fingerprints[name][mode] = {
                "normalized_asm_sha256": sha_text(text),
                "text_sha256": next(
                    (r["text_sha256"] for r in matrix if r["probe"] == name and r["mode"] == mode),
                    None,
                ),
                "bytes": len(text.encode("utf-8")),
            }

        diff_dir = out / "mode_diffs" / name
        diff_dir.mkdir(parents=True, exist_ok=True)
        for left, right in zip(args.modes, args.modes[1:]):
            left_path = out / f"{name}__{left}" / "probe.normalized.s"
            right_path = out / f"{name}__{right}" / "probe.normalized.s"
            if not left_path.is_file() or not right_path.is_file():
                continue
            left_text = left_path.read_text(encoding="utf-8", errors="replace")
            right_text = right_path.read_text(encoding="utf-8", errors="replace")
            diff = difflib.unified_diff(
                left_text.splitlines(keepends=True),
                right_text.splitlines(keepends=True),
                fromfile=left,
                tofile=right,
            )
            (diff_dir / f"{left}_vs_{right}.diff").write_text("".join(diff), encoding="utf-8")

    (out / "fingerprints.json").write_text(
        json.dumps(fingerprints, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (out / "matrix.json").write_text(
        json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"completed {len(matrix)} fingerprint runs; failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
