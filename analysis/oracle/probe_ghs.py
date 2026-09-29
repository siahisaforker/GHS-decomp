#!/usr/bin/env python3
"""Black-box oracle for the Wii U GHS 5.3.22 compiler package."""

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parents[2]
BIN = ROOT / "ghs5.3.22" / "bin"
CX = BIN / "cxppc.exe"

PROBES = {
    "add": "int f(int a,int b){return a+b;}\n",
    "branch": "int f(int a,int b){return a<b ? a+1 : b-1;}\n",
    "loop": "int f(const int *p,int n){int s=0; int i; for(i=0;i<n;i++) s+=p[i]; return s;}\n",
    "switch": "int f(int x){switch(x){case 0:return 7;case 1:return 11;case 4:return 19;default:return -1;}}\n",
    "bits": "unsigned f(unsigned x){return ((x>>5)&0x3f) | ((x&7)<<8);}\n",
    "mul": "int f(int x){return x*10 + x*3;}\n",
    "struct": "struct S{int a; short b; char c;}; int f(struct S *p){return p->a+p->b+p->c;}\n",
    "float": "float f(float a,float b,float c){return a*b+c;}\n",
    "double": "double f(double a,double b){return a/b+1.0;}\n",
    "call": "extern int g(int); int f(int x){return g(x+1)+3;}\n",
}

FLAGSETS = {
    "maxdebug": ["-Omaxdebug"],
    "debug": ["-Odebug"],
    "general": ["-Ogeneral"],
    "speed": ["-Ospeed"],
    "space": ["-Ospace"],
}


def run(cmd, cwd=ROOT):
    env = os.environ.copy()
    env["WINEDEBUG"] = "-all"
    return subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def normalize_asm(text):
    """Remove the run-specific GHS comment header while preserving generated code."""
    output = []
    in_header = True
    for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines():
        # The banner includes a directory continuation line after `#Directory:`
        # and therefore cannot be normalized safely by dropping only named fields.
        # Strip the complete leading comment/blank block, then retain the emitted
        # directives, instructions, labels, and stable compiler comments verbatim.
        if in_header:
            if not line.strip() or line.startswith("#"):
                continue
            in_header = False
        if line.startswith("#Compile Date:"):
            continue
        output.append(line.rstrip())
    return "\n".join(output).rstrip() + "\n"


def write_disassembly(obj, output):
    objdump = shutil.which("llvm-objdump")
    if not objdump or not obj.exists():
        return None
    proc = subprocess.run(
        [objdump, "-dr", str(obj)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output.write_text(proc.stdout)
    return proc.returncode


def dump_text_section(obj, output):
    objcopy = shutil.which("llvm-objcopy")
    if not objcopy or not obj.exists():
        return None
    proc = subprocess.run(
        [objcopy, f"--dump-section=.text={output}", str(obj)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if proc.returncode and output.exists():
        output.unlink()
    return proc.returncode


def compile_one(name, source_text, suffix, flag_name, extras, outroot):
    out = outroot / f"{name}__{flag_name}"
    out.mkdir(parents=True, exist_ok=True)

    src = out / f"probe{suffix}"
    src.write_text(source_text)
    asm = out / "probe.s"
    normalized = out / "probe.normalized.s"
    obj = out / "probe.o"
    text_bin = out / "probe.text.bin"
    backend_obj = out / "backend.o"
    backend_asm = out / "backend.s"
    backend_normalized = out / "backend.normalized.s"
    backend_text_bin = out / "backend.text.bin"
    flags = [*FLAGSETS[flag_name], *extras]

    # `-#` prints the driver's exact ecomppc/asppc command stream and does not
    # execute it. `-noobj` makes the ecomppc -> assembler boundary explicit.
    trace_cmd = [
        "wine",
        str(CX),
        "-#",
        "-noobj",
        "-keeptempfiles",
        "-c",
        "-o",
        str(backend_obj),
        *flags,
        str(src),
    ]
    trace = run(trace_cmd)
    (out / "driver_trace.txt").write_text(trace.stdout)

    asm_cmd = ["wine", str(CX), "-S", "-o", str(asm), *flags, str(src)]
    asm_proc = run(asm_cmd)
    (out / "assembly.log").write_text(asm_proc.stdout)
    (out / "compile.log").write_text(asm_proc.stdout)
    if asm_proc.returncode:
        return asm_proc.returncode, {"probe": name, "flags": flags, "stage": "assembly"}

    normalized.write_text(normalize_asm(asm.read_text(errors="replace")))

    obj_cmd = ["wine", str(CX), "-c", "-o", str(obj), *flags, str(src)]
    obj_proc = run(obj_cmd)
    (out / "object.log").write_text(obj_proc.stdout)
    if obj_proc.returncode:
        return obj_proc.returncode, {"probe": name, "flags": flags, "stage": "object"}

    # This forces GHS to materialize the internal assembly that is normally
    # consumed invisibly by the direct-object path, then assembles it with asppc.
    backend_cmd = [
        "wine",
        str(CX),
        "-v",
        "-noobj",
        "-keeptempfiles",
        "-c",
        "-o",
        str(backend_obj),
        *flags,
        str(src),
    ]
    backend_proc = run(backend_cmd)
    (out / "backend.log").write_text(backend_proc.stdout)
    if backend_proc.returncode:
        return backend_proc.returncode, {"probe": name, "flags": flags, "stage": "backend"}

    if backend_asm.exists():
        backend_normalized.write_text(normalize_asm(backend_asm.read_text(errors="replace")))

    disasm_rc = write_disassembly(obj, out / "disasm.txt")
    text_rc = dump_text_section(obj, text_bin)
    backend_text_rc = dump_text_section(backend_obj, backend_text_bin)
    meta = {
        "probe": name,
        "optimization": flag_name,
        "flags": flags,
        "cxppc": str(CX),
        "commands": {
            "driver_trace": trace_cmd,
            "assembly": asm_cmd,
            "object": obj_cmd,
            "backend_intermediate": backend_cmd,
        },
        "returncodes": {
            "driver_trace": trace.returncode,
            "assembly": asm_proc.returncode,
            "object": obj_proc.returncode,
            "backend_intermediate": backend_proc.returncode,
            "llvm_objdump": disasm_rc,
            "llvm_objcopy_text": text_rc,
            "llvm_objcopy_backend_text": backend_text_rc,
        },
        "sha256": {
            "assembly_raw": sha256(asm),
            "assembly_normalized": sha256(normalized),
            "object": sha256(obj),
            "backend_assembly": sha256(backend_asm),
            "backend_assembly_normalized": sha256(backend_normalized),
            "backend_object": sha256(backend_obj),
            "text": sha256(text_bin),
            "backend_text": sha256(backend_text_bin),
        },
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n")
    return 0, meta


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", choices=sorted(PROBES), default="add")
    parser.add_argument("--source", type=pathlib.Path, help="compile this source instead of a built-in probe")
    parser.add_argument("--flags", choices=sorted(FLAGSETS), default="general")
    parser.add_argument("--matrix", action="store_true", help="run all optimization modes (and all built-in probes unless --source is used)")
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "analysis" / "oracle" / "runs")
    parser.add_argument("--extra", action="append", default=[], help="extra cxppc flag; may be repeated")
    args = parser.parse_args()

    if not shutil.which("wine"):
        parser.error("wine is not available on PATH")
    if not CX.exists():
        parser.error(f"missing compiler driver: {CX}")

    # Starting/stopping Wine's helper processes dominates tiny compiler probes.
    # Persistence is process-local state, not a Wine configuration change, and
    # makes a 50-case matrix practical while preserving identical compiler argv.
    if args.matrix and shutil.which("wineserver"):
        subprocess.run(
            ["wineserver", "-p120"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )

    outroot = args.out.resolve()
    if args.source:
        source_path = args.source.resolve()
        source_text = source_path.read_text()
        suffix = source_path.suffix or ".c"
        inputs = [(source_path.stem, source_text, suffix)]
    else:
        names = sorted(PROBES) if args.matrix else [args.probe]
        inputs = [(name, PROBES[name], ".c") for name in names]

    flag_names = list(FLAGSETS) if args.matrix else [args.flags]
    summary = []
    for name, source_text, suffix in inputs:
        for flag_name in flag_names:
            rc, meta = compile_one(name, source_text, suffix, flag_name, args.extra, outroot)
            summary.append({"probe": name, "optimization": flag_name, "returncode": rc})
            if rc:
                print(json.dumps(meta, indent=2), file=sys.stderr)
                return rc

    if args.matrix:
        (outroot / "matrix_summary.json").write_text(json.dumps(summary, indent=2) + "\n")
        print(f"completed {len(summary)} oracle runs under {outroot}")
    else:
        run_dir = outroot / f"{inputs[0][0]}__{flag_names[0]}"
        print((run_dir / "probe.normalized.s").read_text(errors="replace"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
