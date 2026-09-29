#!/usr/bin/env python3
"""Reproducible black-box harness for GHS 5.3.22 PowerPC on Linux.

The driver is used as the public oracle.  For every source/optimization pair,
the harness also asks cxppc.exe for its hidden ecomppc.exe command with -# and
replays that backend command directly.  This keeps both layers observable
without modifying or redistributing the compiler binaries.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
ORACLE_DIR = ROOT / "analysis" / "oracle"
CORPUS_DIR = ORACLE_DIR / "corpus"
BIN_DIR = ROOT / "ghs5.3.22" / "bin"
CX = BIN_DIR / "cxppc.exe"
ECOM = BIN_DIR / "ecomppc.exe"

MODES = {
    "O0": ["-O0"],
    "O": ["-O"],
    "O2": ["-O2"],
    "Omaxdebug": ["-Omaxdebug"],
    "Odebug": ["-Odebug"],
    "Ogeneral": ["-Ogeneral"],
    "Ospeed": ["-Ospeed"],
    "Ospace": ["-Ospace"],
}


def sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalized_asm_sha256(path: Path) -> str | None:
    if not path.exists():
        return None
    lines = []
    for line in path.read_text(errors="replace").splitlines():
        if line.startswith("#Driver Command:") or line.startswith("#Compile Date:"):
            continue
        lines.append(line.rstrip())
    normalized = ("\n".join(lines) + "\n").encode()
    return hashlib.sha256(normalized).hexdigest()


def pick_runner(name: str) -> list[str]:
    if name == "none":
        return []
    if name == "auto":
        if shutil.which("wibo"):
            return ["wibo"]
        if shutil.which("wine"):
            return ["wine"]
        raise SystemExit("neither wibo nor wine is available")
    exe = shutil.which(name)
    if not exe:
        raise SystemExit(f"runner not found: {name}")
    return [name]


def shell_command(argv: Iterable[str]) -> str:
    return shlex.join(list(argv))


def run(argv: list[str], cwd: Path, timeout: int) -> dict:
    env = os.environ.copy()
    env.setdefault("WINEDEBUG", "-all")
    try:
        p = subprocess.run(
            argv,
            cwd=cwd,
            env=env,
            text=True,
            errors="replace",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return {
            "argv": argv,
            "command": shell_command(argv),
            "returncode": p.returncode,
            "stdout": p.stdout,
            "stderr": p.stderr,
        }
    except subprocess.TimeoutExpired as e:
        return {
            "argv": argv,
            "command": shell_command(argv),
            "returncode": 124,
            "stdout": e.stdout or "",
            "stderr": (e.stderr or "") + "\nTIMEOUT\n",
        }


def write_run_log(path: Path, rec: dict) -> None:
    text = f"$ {rec['command']}\n"
    if rec["stdout"]:
        text += "\n[stdout]\n" + rec["stdout"]
    if rec["stderr"]:
        text += "\n[stderr]\n" + rec["stderr"]
    text += f"\n[returncode] {rec['returncode']}\n"
    path.write_text(text, encoding="utf-8")


def parse_ecom_argv(trace: str) -> list[str]:
    # cxppc -# wraps ecom with a backslash at each continued line.  C++ traces
    # may print a second cleanup command afterwards, so stop when the first
    # command's continuation chain ends.
    command_lines: list[str] = []
    started = False
    for raw_line in trace.replace("\r", "").splitlines():
        if not started:
            if "ecomppc.exe" not in raw_line.lower():
                continue
            started = True
        line = raw_line.rstrip()
        continued = line.endswith("\\")
        command_lines.append(line[:-1] if continued else line)
        if not continued:
            break
    joined = " ".join(command_lines)
    toks = joined.split()
    if not toks or not toks[0].lower().endswith("ecomppc.exe"):
        raise ValueError("cxppc -# output did not begin with ecomppc.exe")
    return toks[1:]


def rewrite_gh_out(args: list[str], output_name: str) -> list[str]:
    out = list(args)
    try:
        i = out.index("--gh_out")
    except ValueError as e:
        raise ValueError("ecom argv has no --gh_out") from e
    if i + 1 >= len(out):
        raise ValueError("ecom argv ends after --gh_out")
    out[i + 1] = output_name
    return out


def disassemble(obj: Path, cwd: Path, timeout: int) -> dict | None:
    tool = shutil.which("llvm-objdump")
    if not tool or not obj.exists():
        return None
    return run([tool, "-dr", obj.name], cwd, timeout)


def compile_one(
    source: Path,
    mode: str,
    flags: list[str],
    runner: list[str],
    out_root: Path,
    timeout: int,
) -> dict:
    run_dir = out_root / source.stem / mode
    run_dir.mkdir(parents=True, exist_ok=True)
    local_source = run_dir / ("input" + source.suffix.lower())
    shutil.copyfile(source, local_source)

    records: dict[str, dict] = {}

    trace_cmd = runner + [str(CX), "-#", *flags, "-S", "-o", "assembly.s", local_source.name]
    records["driver_trace"] = run(trace_cmd, run_dir, timeout)
    trace_text = records["driver_trace"]["stdout"] + records["driver_trace"]["stderr"]
    (run_dir / "driver_trace.txt").write_text(trace_text, encoding="utf-8")
    write_run_log(run_dir / "driver_trace.log", records["driver_trace"])

    asm_cmd = runner + [str(CX), *flags, "-S", "-o", "assembly.s", local_source.name]
    records["assembly"] = run(asm_cmd, run_dir, timeout)
    write_run_log(run_dir / "assembly.log", records["assembly"])

    obj_cmd = runner + [str(CX), *flags, "-c", "-o", "object.o", local_source.name]
    records["object"] = run(obj_cmd, run_dir, timeout)
    write_run_log(run_dir / "object.log", records["object"])

    # Force the historical compiler -> assembler pipeline so the temporary .s
    # file is retained beside the assembled object.
    pipeline_cmd = runner + [
        str(CX),
        *flags,
        "-noobj",
        "-keeptempfiles",
        "-c",
        "-o",
        "pipeline.o",
        local_source.name,
    ]
    records["pipeline"] = run(pipeline_cmd, run_dir, timeout)
    write_run_log(run_dir / "pipeline.log", records["pipeline"])
    pipeline_asm = run_dir / "pipeline.s"
    if pipeline_asm.exists():
        pipeline_asm.rename(run_dir / "pipeline_temp.s")

    direct_error = None
    if records["driver_trace"]["returncode"] == 0:
        try:
            backend_args = rewrite_gh_out(parse_ecom_argv(trace_text), "direct_ecom.s")
            direct_cmd = runner + [str(ECOM), *backend_args]
            records["direct_ecom"] = run(direct_cmd, run_dir, timeout)
            write_run_log(run_dir / "direct_ecom.log", records["direct_ecom"])
            (run_dir / "direct_ecom.argv.json").write_text(
                json.dumps(backend_args, indent=2), encoding="utf-8"
            )
        except ValueError as e:
            direct_error = str(e)

    dis = disassemble(run_dir / "object.o", run_dir, timeout)
    if dis is not None:
        records["disassembly"] = dis
        (run_dir / "disassembly.txt").write_text(
            dis["stdout"] + dis["stderr"], encoding="utf-8"
        )

    artifacts = {
        name: {
            "exists": (run_dir / name).exists(),
            "size": (run_dir / name).stat().st_size if (run_dir / name).exists() else None,
            "sha256": sha256(run_dir / name),
            **(
                {"normalized_asm_sha256": normalized_asm_sha256(run_dir / name)}
                if name.endswith(".s")
                else {}
            ),
        }
        for name in [
            "assembly.s",
            "object.o",
            "pipeline.o",
            "pipeline_temp.s",
            "direct_ecom.s",
            "disassembly.txt",
        ]
    }

    failures = {
        name: rec["returncode"]
        for name, rec in records.items()
        if rec["returncode"] != 0
    }
    if direct_error:
        failures["direct_ecom_parse"] = direct_error

    result = {
        "source": str(source.relative_to(ROOT)),
        "mode": mode,
        "flags": flags,
        "runner": runner,
        "commands": {name: rec["command"] for name, rec in records.items()},
        "returncodes": {name: rec["returncode"] for name, rec in records.items()},
        "artifacts": artifacts,
        "assembly_matches": {
            "direct_ecom": artifacts["assembly.s"].get("normalized_asm_sha256")
            == artifacts["direct_ecom.s"].get("normalized_asm_sha256"),
            "pipeline_temp": artifacts["assembly.s"].get("normalized_asm_sha256")
            == artifacts["pipeline_temp.s"].get("normalized_asm_sha256"),
        },
        "failures": failures,
    }
    (run_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result


def corpus_sources(selected: list[str]) -> list[Path]:
    sources = sorted([*CORPUS_DIR.glob("*.c"), *CORPUS_DIR.glob("*.cpp")])
    if not selected:
        manifest = CORPUS_DIR / "manifest.json"
        if manifest.exists():
            entries = json.loads(manifest.read_text(encoding="utf-8"))
            return [CORPUS_DIR / entry["file"] for entry in entries]
        return sources
    wanted = set(selected)
    found = [p for p in sources if p.stem in wanted or p.name in wanted]
    missing = wanted - {p.stem for p in found} - {p.name for p in found}
    if missing:
        raise SystemExit("unknown case(s): " + ", ".join(sorted(missing)))
    return found


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runner", default="auto", choices=["auto", "wine", "wibo", "none"])
    ap.add_argument("--mode", action="append", choices=sorted(MODES), dest="modes")
    ap.add_argument("--case", action="append", default=[], dest="cases")
    ap.add_argument("--extra", action="append", default=[], help="extra compiler flag; repeatable")
    ap.add_argument("--out", type=Path, default=ORACLE_DIR / "runs_blackbox")
    ap.add_argument("--timeout", type=int, default=30)
    args = ap.parse_args()

    if not CX.exists() or not ECOM.exists():
        raise SystemExit(f"missing compiler binaries under {BIN_DIR}")

    runner = pick_runner(args.runner)
    modes = args.modes or ["O0", "O", "O2"]
    sources = corpus_sources(args.cases)
    args.out.mkdir(parents=True, exist_ok=True)

    all_results = []
    for source in sources:
        for mode in modes:
            flags = [*MODES[mode], *args.extra]
            result = compile_one(source, mode, flags, runner, args.out, args.timeout)
            all_results.append(result)
            state = "ok" if not result["failures"] else "FAIL"
            print(f"{source.name:20s} {mode:10s} {state}")

    summary = {
        "runner": runner,
        "compiler": str(CX.relative_to(ROOT)),
        "backend": str(ECOM.relative_to(ROOT)),
        "modes": modes,
        "cases": [str(p.relative_to(ROOT)) for p in sources],
        "runs": len(all_results),
        "failures": [r for r in all_results if r["failures"]],
        "results": all_results,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return 1 if summary["failures"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
