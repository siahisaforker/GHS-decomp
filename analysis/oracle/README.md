# GHS 5.3.22 compiler oracle

This directory wraps the exact Wii U Green Hills 5.3.22 package in `ghs5.3.22/bin` as a reproducible black-box code-generation oracle. It uses the machine's existing `/usr/bin/wine`; no Wine prefix or system configuration changes are required.

## Minimal commands

From `/spaghettikart/ghs-re`, the smallest useful assembly compile is:

```sh
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -S -o out.s input.c
```

The corresponding direct-object compile is:

```sh
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -c -o out.o input.c
```

This package's driver defaults to `-cpu=espresso`. Generated assembly identifies the compiler as `C-POWERPC 5.3.22 RELEASE VERSION`, `MULTI v5.3.22 Nintendo`, revision/release date 2013-09-26. Objects are big-endian 32-bit PowerPC ELF.

`cxppc -# ...` prints the exact internal commands without executing them. `cxppc -v ...` prints the same commands while executing them. A normal `-c` compile uses the compiler's direct-object path, so the temporary assembly named in the trace is not materialized.

To expose the backend-to-assembler boundary, force the non-direct-object path and keep its intermediate:

```sh
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe \
  -v -noobj -keeptempfiles -c -Ogeneral -o out.o input.c
```

That leaves `out.s`, produced by `ecomppc.exe`, then invokes `asppc.exe` on it. This is the cleanest way to capture the real internal assembly stream. A bare call such as `wine ecomppc.exe --c ...` only prints GHS's "INTERNAL interface" warning because the driver supplies a large target/language configuration and hidden `-X`/`-Z` options. Use `-#` when the exact `ecomppc.exe` argv is needed.

## Harness

For the full driver/backend oracle, including direct replay of the internal
`ecomppc.exe` argv recovered from `cxppc -#`, run:

```sh
python3 analysis/oracle/run_blackbox.py
```

The default manifest currently runs 9 C/C++ cases at `-O0`, `-O`, and `-O2`
(27 runs). Each run verifies the public driver, direct object generation, the
retained `ecomppc -> asppc` pipeline, direct `ecomppc.exe` replay, and
disassembly. `result.json` records the exact commands and whether normalized
assembly from those paths matches. See `VALIDATION.md` for the checked host
results and `runs_blackbox/summary.json` for the aggregate record.

`probe_ghs.py` is the smaller fingerprint-oriented harness. It is convenient
for focused probes, the five named GHS optimization presets, and quick
candidate iteration:

Run one built-in probe at the normal general optimization level:

```sh
python3 analysis/oracle/probe_ghs.py --probe add --flags general
```

Run the 10-probe corpus under all five documented optimization modes:

```sh
python3 analysis/oracle/probe_ghs.py --matrix
```

For matrix runs the harness asks the existing Wine server to remain alive for 120 seconds. This only avoids repeated Wine process startup; it does not alter the Wine prefix or compiler configuration.

Compile a decompilation candidate instead of a built-in probe:

```sh
python3 analysis/oracle/probe_ghs.py \
  --source path/to/candidate.c --flags speed --extra=-sda=0
```

The optimization presets are `-Omaxdebug`, `-Odebug`, `-Ogeneral`, `-Ospeed`, and `-Ospace`. The current tiny corpus covers arithmetic, branches, loops, switches, rotate/mask-style bit operations, integer multiplies, struct loads, float/double arithmetic, and an external call.

Each run directory contains:

- `probe.s`: normal `cxppc -S` output.
- `probe.normalized.s`: the same assembly with path/date/driver-header fields removed so its SHA-256 is stable across runs.
- `probe.o`, `probe.text.bin`, and `disasm.txt`: the direct GHS object, raw `.text` section, and LLVM disassembly.
- `driver_trace.txt`: dry-run `-#` output showing the exact `ecomppc.exe` and `asppc.exe` invocations.
- `backend.s`, `backend.normalized.s`, `backend.o`, and `backend.text.bin`: the preserved `ecomppc -> asppc` intermediate path from `-noobj -keeptempfiles` and its stable code fingerprints.
- `backend.log`: executing `-v` trace for that split path.
- `meta.json`: commands, return codes, flags, and hashes.

Whole object files are not deterministic across runs because GHS embeds run-specific metadata. For code matching, use the normalized assembly hash or the direct-object `probe.text.bin` hash from `meta.json`.

The split-path `backend.o` is deliberately diagnostic rather than a byte-for-byte replacement for the compiler's direct object. For local branches, the direct-object path writes the branch displacement into the instruction word and also emits the `R_PPC_REL14` relocation. `asppc.exe` leaves the displacement field zero and relies on the relocation. For example, the loop probe's direct object contains `40 80 00 1c` / `41 80 ff ec`, while the split assembly object contains `40 80 00 00` / `41 80 00 00` at the same relocation sites. The normalized `probe.s` and `backend.s` are identical, confirming that this difference is in object emission/assembly rather than optimizer code generation.

## Validation on this machine

The full 10-probe x 5-mode matrix completed successfully: 50/50 runs returned zero and produced the expected assembly, object, backend-intermediate, trace, disassembly, and metadata files. Normalized `probe.s` and `backend.s` matched in all 50 runs.

Repeated `loop`/`-Ogeneral` runs produced the same normalized assembly SHA-256 (`4f069d77b22d2bde8a74839cb4dd923914db249fd9cc8d5371511022d4ae43d0`) and the same direct `.text` SHA-256 (`78f190162ab8391e0c25837038f54cd35a95e1fbcab2495c85171f477f7dca94`), while the whole-object hashes differed as expected from embedded run metadata.

The loop probe makes the optimization modes visibly distinct at the machine-code level:

| mode | assembly header | direct `.text` bytes |
|---|---|---:|
| `-Omaxdebug` | `# ecom  -g -w` | 76 |
| `-Odebug` | `# ecom  -g -w` | 56 |
| `-Ogeneral` | `# ecom  -w -OM` | 48 |
| `-Ospeed` | `# ecom  -w -OLM` | 152 |
| `-Ospace` | `# ecom  -w -OMS` | 44 |

`-Ospeed` expands the simple accumulation loop substantially, while `-Ospace` produces the smallest form. The bit-manipulation probe under `-Ospeed` lowers to `rlwinm` followed by `rlwimi`, which is a useful GHS code-generation fingerprint.

The same harness also accepts C++ input by extension. A `.cpp` smoke test compiled successfully as `C++POWERPC 5.3.22 RELEASE VERSION`; a trivial inline member call became `lwz r12, 0(r3); addi r3, r12, 1; blr` with GHS-style symbol `h__FP1X`.
