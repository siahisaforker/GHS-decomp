# GHS 5.3.22 `ecomppc.exe` static backend map

This directory maps the Nintendo PowerPC compiler executable shipped as
`ghs5.3.22/bin/ecomppc.exe`. The analysis is address/metadata only; no
proprietary executable bytes are copied here.

The exact binary analyzed has SHA-256
`b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3`.
All virtual addresses below assume the PE image base `0x00400000`.

## Executable layout and entry path

The file is a stripped PE32/i386 console executable with four sections:

| Section | VA | Virtual size | Raw size | Raw file offset | Meaning |
| --- | ---: | ---: | ---: | ---: | --- |
| `.text` | `0x00401000` | `0x006b5934` | `0x006b6000` | `0x00001000` | host x86 code |
| `.rdata` | `0x00ab7000` | `0x00007a96` | `0x00008000` | `0x006b7000` | imports/read-only data |
| `.data` | `0x00abf000` | `0x0028b688` | `0x00118000` | `0x006bf000` | initialized + zero-fill globals |
| `.sxdata` | `0x00d4b000` | `0x0000013c` | `0x00001000` | `0x007d7000` | SafeSEH metadata |

The import table names `WS2_32.dll`, `NETAPI32.dll`, `MPR.dll`,
`KERNEL32.dll`, `USER32.dll`, and `ADVAPI32.dll`. The imports are ordinary
Windows runtime, filesystem/process, registry, UI, networking, and license
support APIs; there is no separate PowerPC code-generation DLL in the import
set. The backend is resident in this executable. `imports.txt` preserves the
complete `objdump -p` import-table decode, including names, hints, ordinals,
and IAT RVAs.

The PE entry point is `0x00a938ff`. Raw disassembly makes the startup chain
fairly clear:

```text
0x00a938ff  call 0x00aa424c    MSVC security-cookie initialization
0x00a93904  jmp  0x00a937ad    CRT startup
...
0x00a938a3  call 0x00995fd0    probable program main wrapper
```

`0x00aa424c` has the recognizable MSVC cookie logic around constant
`0xbb40e64e` and mixes system time, process/thread IDs, tick count, and the
performance counter. The CRT function at `0x00a937ad` performs normal PE/CRT
initialization before passing its command-line state into `0x00995fd0`.

`0x00995fd0` is only 34 bytes. It calls an init helper, calls `0x005b99a2`
with the two arguments it received from CRT, runs a shutdown helper, and
returns zero. `0x005b99a2` is therefore a useful compiler bootstrap anchor;
its trace string is `gen_init`, and it sets up the internal compiler/runtime
state.

## Function-boundary inventory

The existing Ghidra analysis identifies **21,953 functions**, including 29
thunks. Because the executable is stripped, most names are heuristic or were
added by the repository's analysis scripts. There are 409 functions with
bodies of five bytes or less and 1,522 of sixteen bytes or less. Those tiny
functions are especially common in the target interface and are often no-op,
constant-return, or assertion stubs, so adjacency alone is not a safe naming
signal.

The useful boundary evidence comes from three sources together:

1. Ghidra's recursive traversal/function recovery (`inventory/functions.tsv`),
2. direct call targets and standard x86 prologues in `llvm-objdump`, and
3. string cross-references from `all_string_xrefs.tsv`.

`backend_functions.csv` records the important recovered functions, their
bodies/call counts, and the reason for each label.

## High-level optimizer and code-generation pipeline

The central compilation path is now concrete enough to use as a decompilation
road map:

```text
codegen 0x006ae504
  |
  +-- independent_optimize 0x006ad8d8
  |     +-- dooptimize 0x00545735
  |     +-- target-independent cleanup/dataflow
  |
  +-- makeproc 0x006a0b1d
  |
  +-- allocate_registers 0x006adf1c
  |     +-- register_allocation_core 0x0069bf55
  |     +-- fixup_driver 0x006ac8eb
  |     +-- backend_dataflow_peephole 0x006aca15
  |     +-- branch_optimize_driver 0x006ace63
  |           +-- branches_and_post_alloc 0x006747de
  |
  +-- codewrite 0x006ae05c
```

`codegen` has three recovered callers: `0x004d7f00`, `0x0099c369`, and
`0x0099d568`. These are good upward-tracing anchors for locating the
front-end/translation-unit handoff without guessing from the CRT path.

`independent_optimize` calls `dooptimize` after IR/control-flow setup and then
performs additional independent cleanup. Named optimizer anchors already
recovered around that area include:

| VA | Label | Evidence/use |
| ---: | --- | --- |
| `0x0051c208` | `propagateconstants` | constant propagation |
| `0x00500fbc` | `run_liveness_dataflow` | liveness analysis |
| `0x0053eade` | `loop_unroll` | loop unrolling |
| `0x0054c4a7` | `SIMD_vectorize` | SIMD/vector optimization |
| `0x005522d5` | `find_loop_invariants` | invariant discovery |
| `0x005558f2` | `possible_induction_var` | induction-variable recognition |
| `0x00557560` | `check_possible_alias` | alias checks |
| `0x00568597` | `object_motion` | motion optimization |
| `0x00589e83` | `substitute_driver` | substitution/copy-style driver |
| `0x005cb7e0` | `treepeep` | tree peephole pass |
| `0x0066b178` | `dflow_vn_forward` | forward value numbering/dataflow |
| `0x006ef6cb` | `optimize_tail_calls` | tail-call optimization |

The allocator wrapper `0x006adf1c` calls the core allocator and then always
walks through target fixup, backend dataflow/peephole, and branch optimization
when code exists. The core allocator is independently anchored by the runtime
trace string `register allocation` at `0x00b06f2f`, referenced from
`0x0069bf73` and `0x0069c274` inside `0x0069bf55`.

The graph-allocation implementation has explicit recovered stages:

- `coalesce_stage` at `0x0074c01c`, with debug text
  `%;COALESCE stage :` at `0x00b0d776`.
- `spill_stage` at `0x0074c6e1`, with debug text beginning
  `%;SPILL stage :` at `0x00b0d7a3`.
- `spill_candidate` at `0x0071661c`.
- `allocate_variable` at `0x0071bc67`.

## Scheduler map

Scheduling exists both before and after allocation. `pre_alloc_scheduling`
at `0x006a51dd` selects `schedule_pass_1` or `schedule_pass_3`. The branch/post
allocation driver repeats scheduling near the end of `0x006747de`:

```text
if alternate scheduler disabled:
    schedule_pass_1 0x0066fad9
    optional schedule_pass_2 0x00739e6a
else:
    schedule_pass_3 0x0073a363
```

`schedule_pass_1` is a block/window scheduler with gap-filling behavior.
`schedule_pass_2` and `schedule_pass_3` both use a scheduler/model object in
`DAT_00ce2320`; their diagnostics literally say `List scheduling`. Embedded
selector strings include `compat_list_scheduler`, `list_scheduler`, and
`resource_model_scheduler`. Target model strings include
`g4_resource_scheduler` and `ppc970_resource_scheduler`.

The post-allocation path then removes no-ops. This ordering matters when trying
to reproduce GHS instruction order: branch cleanup and code expansion happen
before the final scheduling pass, while another scheduling opportunity exists
before register allocation.

## Concrete PowerPC target object

The most useful backend discovery is the target interface object used by the
generic optimizer/codegen code.

`DAT_00bdb584` is the global current-target pointer. A full `.text` scan found
many reads but a single initialization store:

```text
FUN_00424ceb:
    ...
    push 0x251c
    call 0x005b96ff        ; allocate target object
    ...
    mov dword ptr [ebx], 0x00b0af4c
    mov dword ptr [ebx], 0x00abf65c   ; final method table
    mov [0x00bdb584], eax             ; 0x00424e25
```

Because this is `ecomppc.exe`, the object is the concrete PowerPC target
implementation. Its final method table begins at `0x00abf65c`. Calls use a
Green Hills-style pair of a small `this` adjustment and a function pointer;
for example the allocator calls the pointer at table offset `+0x524` while
reading the preceding adjustment at `+0x520`.

The table is regular through record offset `0x830` and stops before unrelated
data at `+0x838`. It contains one initial non-code metadata record followed by
**262 concrete method records**. All recovered adjustment words in this span
are zero. `target_vtable.csv` contains the complete table.

The method slots already tied to generic backend phases are:

| Method offset | Concrete target | Called from | Current interpretation |
| ---: | ---: | --- | --- |
| `+0x394` | `0x00739d9d` | list scheduler | relink/commit scheduled instruction list |
| `+0x46c` | `0x00470998` | branch optimizer | target branch/SSIID rewrite hook |
| `+0x474` | `0x004065b4` | fixup driver | no-op target fixup hook in this build |
| `+0x484` | `0x00424b5d` | post-branch code expansion | optional target expansion cleanup |
| `+0x524` | `0x0040661c` | register allocator | no-op post-allocation target hook in this build |
| `+0x5e4` | `0x00422ff4` | `codewrite` | main final target code-writing/emission hook |
| `+0x67c` | `0x005bd98d` | branch pass | target instruction predicate/filter |
| `+0x6c4` | `0x0040668a` | fixup driver | optional no-op target fixup hook in this build |
| `+0x834` | `0x00424c57` | branch merge logic | target branch-merge helper |

The three no-op hooks above are actual five-byte `push ebp; mov ebp,esp;
leave; ret` functions. That is useful negative evidence: behavior expected at
those interface points is intentionally absent for this target/configuration,
so matching GHS output should focus first on the nontrivial slots.

`+0x5e4 -> 0x00422ff4` is the highest-value next function for instruction
encoding/output reconstruction. `codewrite` invokes it with the finalized
procedure after allocation, fixups, peepholes, branches, expansion, and
scheduling have completed.

## PowerPC/Nintendo tuning clues

`ppc_strings.csv` contains the extracted PPC/backend-relevant strings and all
available Ghidra xrefs. Several strings directly expose supported CPUs,
ABIs, target errata, scheduler models, and optimizer knobs. High-value names
include:

- CPU/ISA families: `ppc403`, `ppc405`, `ppc603`, `ppc604`, `ppc750`,
  `ppc7450`, `ppc970`, `ppce500`, `ppce500mc`, `ppc8540`, `ppc476fp`,
  `ppcvle`, and `ppcsfp`.
- Nintendo-specific tuning: `espresso_peepholes`.
- Scheduling: `ppc_sched_7450`, `ppc_no_schedule_past_branches`,
  `g4_resource_scheduler`, and `ppc970_resource_scheduler`.
- Prologue/epilogue choices: `ppc_better_prologue`, `nosmallprologue`,
  `smallerprologue`, `ppc_small_restore_blr`, `ppc_blr_epilogue_regs`,
  `__ghs_prologue_func`, and `__ghs_epilogue_func`.
- Peepholes/code shape: `ppc_rotate_peep`, `ppc_rlwimi_peep`,
  `ppc_vector_peephole`, `ppc_fewer_movandtrunc`, `ppc_fsel`, and
  `ppc_isel`.
- Allocation/spill tuning: `better_graph_alloc_coalesce`,
  `dont_coalesce_unequal_sizes`, `no_replace_const_spills`,
  `real_replace_const_spills`, and `handlespillsbetter`.
- ABI/code generation: `ppceabi11`, `linux_ppc64_abi`, `ppcabipic`,
  `ppcfarcalls`, `ppclargegot`, `CodegenSupports64BitInts`, and
  `target_supports_binary_codegen`.

These are option/configuration names, not automatically active settings. They
are most useful as search anchors into the target object's methods and global
configuration initialization.

The internal option table also gives exact storage addresses. Named option ID
`N` is tested at byte `0x00c4064e + N`. The Nintendo/Espresso group is:

| Option | ID | option byte VA |
| --- | ---: | ---: |
| `espresso` | 4649 | `0x00c41877` |
| `espresso_support_ps` | 4658 | `0x00c41880` |
| `espresso_basic_ps_opt` | 4711 | `0x00c418b5` |
| `espresso_combine_merge` | 4712 | `0x00c418b6` |
| `espresso_combine_load` | 4713 | `0x00c418b7` |
| `espresso_combine_store` | 4714 | `0x00c418b8` |
| `espresso_loadstore_opt` | 4715 | `0x00c418b9` |
| `espresso_peepholes` | 4725 | `0x00c418c3` |
| `espresso_fsplat` | 4726 | `0x00c418c4` |
| `espresso_merge_epilogue` | 4727 | `0x00c418c5` |
| `espresso_cmp` | 4728 | `0x00c418c6` |
| `espresso_ps_pre` | 4729 | `0x00c418c7` |
| `espresso_ps_structinreg` | 4997 | `0x00c419d3` |

`target_options.csv` records the same mapping for 119 PowerPC/Espresso-related
option names, including the option-table file offset and string VA. It is
generated by `build_binary_inventory.py`.

## RTTI, type, and vtable evidence

The host executable itself has only a small amount of recognizable MSVC RTTI.
The four recovered type-descriptor strings are:

| VA | MSVC type string |
| ---: | --- |
| `0x00bd519c` | `.?AVbad_alloc@std@@` |
| `0x00bd51b8` | `.?AVexception@std@@` |
| `0x00bd5fcc` | `.?AVtype_info@@` |
| `0x00bd5fe8` | `.?AVbad_exception@std@@` |

Ghidra also identifies host vftable/RTTI structures around `0x00ab9ee0`,
`0x00abc2e8`, `0x00abc308`, `0x00abc334`, and RTTI locator/hierarchy records
around `0x00abcb64` through `0x00abcc70`.

Strings such as `` `vftable' ``, `` `RTTI` ``, `no_rtti`,
`ABI_CHANGES_FOR_RTTI`, and `__RTTI` are mostly compiler/demangler behavior for
the *program being compiled*. They should not be confused with host C++ RTTI
for `ecomppc.exe` itself. The large target method table at `0x00abf65c` was
found from concrete dispatch behavior, not from an MSVC RTTI name.

## Embedded source breadcrumbs

The executable retains source-file assertion/debug strings. Existing analysis
maps 1,736 function/source associations across 84 embedded source paths.
Backend-relevant paths include:

```text
src/compilers/edg/ghs_be.cc
src/compilers/indep/indopc.cc
src/compilers/indep/indstatic.cc
src/shared/genout.c
src/shared/indgen.c
src/shared/indoutputgen.cc
src/shared/indinst/indinst.cc
src/shared/indinst/indinstop.cc
```

`src/compilers/edg/ghs_be.cc` alone maps strongly into the `0x009a...` to
`0x009b...` region and is a useful front-end/backend handoff cluster. The
binary also contains generic `../src/target` breadcrumbs, but no clean
PowerPC backend source filename was recovered from the current string pass.

## Reproducing the structured map

Run from the repository root:

```sh
python3 analysis/backend_map/build_map.py
```

The script verifies the executable SHA-256 before emitting:

- `summary.json`: PE layout, counts, startup anchors, and target-object facts.
- `imports.txt`: complete PE import-table decode from `objdump`.
- `backend_functions.csv`: key optimizer/backend functions and evidence.
- `target_vtable.csv`: all recovered PowerPC target method records.
- `ppc_strings.csv`: PPC/backend option and diagnostic string anchors.

Useful raw verification commands are:

```sh
objdump -h ghs5.3.22/bin/ecomppc.exe
objdump -p ghs5.3.22/bin/ecomppc.exe
llvm-objdump --disassemble --x86-asm-syntax=intel \
  --start-address=0x006ae504 --stop-address=0x006ae5c9 \
  ghs5.3.22/bin/ecomppc.exe
```

The next productive RE seam is the concrete target table rather than a broad
linear sweep. Start with `+0x5e4 -> 0x00422ff4` for final emission, then trace
the nontrivial `0x0042xxxx`, `0x0047xxxx`, and scheduler callbacks in
`target_vtable.csv`. Those calls already sit at known pipeline boundaries, so
their inputs and effects can be compared against small GHS-generated PPC
fixtures without having to name the entire compiler first.
