# GHS-decomp

Experimental reverse engineering of **Green Hills MULTI / C-POWERPC 5.3.22 Nintendo**, mainly because understanding this compiler should make Wii U matching decompilation less painful.

The goal is **not** to recover or redistribute Green Hills' original source tree. The useful target is a behavioral model of the compiler: pass ordering, optimization fingerprints, instruction selection, register allocation, scheduling, ABI decisions, and the source shapes that produce specific PowerPC output.

> This repo does **not** contain the proprietary GHS compiler binaries. Bring your own legally obtained copy. The current research target matches the GHS 5.3.22 Wii U package used by decomp.me.

## What already works

We have both sides of the experiment running:

- static analysis of the stripped `ecomppc.exe` in Ghidra;
- a black-box compiler oracle that runs the real Windows compiler under Wine;
- exact preservation of the assembly emitted by `ecomppc` before `asppc`;
- source -> assembly fingerprints across GHS optimization modes;
- embedded-source-path and pass-string mapping;
- an initial backend call graph with recovered semantic names.

Some of the highest-value recovered anchors are:

| address | recovered role |
|---|---|
| `0x006ae504` | `codegen` |
| `0x006ad8d8` | `independent_optimize` |
| `0x00545735` | `dooptimize` |
| `0x006a0b1d` | `makeproc` |
| `0x006adf1c` | `allocate_registers` |
| `0x0069bf55` | `register_allocation_core` |
| `0x006aca15` | `backend_dataflow_peephole` |
| `0x006ace63` | `branch_optimize_driver` |
| `0x006747de` | `branches_and_post_alloc` |
| `0x006ae05c` | `codewrite` |

See [`docs/STATUS.md`](docs/STATUS.md) and [`docs/PIPELINE.md`](docs/PIPELINE.md).

## Repo layout

- `analysis/ghidra/scripts/` - headless Ghidra scripts
- `analysis/ghidra/labels.tsv` - recovered semantic labels
- `analysis/manual/` - reproducible static-analysis helpers and compact derived metadata
- `analysis/oracle/` - black-box compiler harness and source corpus
- `analysis/prime/` - higher-level derived maps from the current investigation
- `docs/` - human-readable findings

Generated Ghidra databases, compiler binaries, Wine state, large raw dumps, and per-run oracle output stay out of git.

## Why this matters for Wii U decomp

A matching decompilation problem is partly a compiler-behavior problem. If an agent knows that GHS 5.3.22 tends to lower a certain expression into a particular `rlwinm`/`rlwimi` pattern, chooses registers in a specific order, schedules loads a certain way, or changes behavior under one hidden pass gate, the search space for reconstructing source gets much smaller.

The intended long-term loop is:

```text
Wii U function assembly
        |
        v
AI proposes source
        |
        v
GHS 5.3.22 compile oracle
        |
        v
assembly diff
        |
        v
compiler-aware diagnosis + mutation
        |
        +---------------------> repeat until match
```

## Legal / project boundary

No proprietary GHS executables, archives, SDK libraries, PDBs, or recovered copyrighted source dumps belong in this repository. Derived metadata, addresses, independently written analysis scripts, behavioral tests, and pseudocode notes are the intended artifacts.
