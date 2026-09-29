# `ecomppc.exe` static map — GHS 5.3.22 Wii U compiler

Target: local copy at `ghs5.3.22/bin/ecomppc.exe`.  This map is for reverse-engineering the compiler's behavior and pass structure; it does not contain or redistribute the binary.

## Identity and PE layout

- SHA-256: `b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3`
- Size: `8,224,768` bytes
- Format: stripped PE32 / x86, image base `0x00400000`
- PE timestamp: `2013-09-26 00:40:19 UTC` (`0x5243E4E3` / 1380181219)
- Entry point: RVA `0x006938FF`, VA `0x00A938FF`
- Linker version in PE optional header: 6.0
- Relocations, COFF symbols/line numbers, and PE debug directory are stripped/absent.

| Section | VA | RVA | Virtual size | Raw file offset | Raw size | Use |
|---|---:|---:|---:|---:|---:|---|
| `.text` | `0x00401000` | `0x00001000` | `0x006B5934` | `0x00001000` | `0x006B6000` | executable compiler/runtime code |
| `.rdata` | `0x00AB7000` | `0x006B7000` | `0x00007A96` | `0x006B7000` | `0x00008000` | imports, const data, MSVC RTTI/vtables |
| `.data` | `0x00ABF000` | `0x006BF000` | `0x0028B688` | `0x006BF000` | `0x00118000` | strings, compiler tables, globals, zero-fill tail |
| `.sxdata` | `0x00D4B000` | `0x0094B000` | `0x0000013C` | `0x007D7000` | `0x00001000` | x86 safe-SEH metadata |

The import directory is at RVA `0x006BD85C` / VA `0x00ABD85C`; the IAT begins at RVA `0x006B7000` / VA `0x00AB7000`.

Imports are conventional host/runtime support rather than compiler plugins: `KERNEL32.dll` (173 thunks), `WS2_32.dll` (29, mostly ordinal Winsock imports plus `WSAIoctl`/`WSASocketA`), `ADVAPI32.dll` (10), `USER32.dll` (5), and one each from `NETAPI32.dll` (`Netbios`) and `MPR.dll` (`WNetGetUserA`).  The KERNEL32 set covers file/mmap/process/thread/TLS/locale/heap primitives; ADVAPI32 is registry/security; USER32 is minimal UI support.  The network imports align with the license-manager strings elsewhere in the image, so they should not be mistaken for code-generation dependencies.

## Function recovery

Ghidra 12.0.4 currently recovers **21,953 functions** in `.text`:

- 21,312 default names (`FUN_xxxxxxxx`)
- 606 analyzer-generated names
- 34 high-confidence user labels for compiler passes
- 1 imported function represented as a function
- 29 thunks

The complete table is `analysis/ghidra/out/inventory/functions.tsv`; it records entry, body min/max, body byte count, name/source, caller-reference count, direct-callee count, and thunk status.  This is the function-boundary source to use for future xref/decompilation work instead of rescanning prologues.

The most useful recovered pass boundaries are:

| VA range | Label | Body bytes | Callers | Direct callees | Evidence |
|---|---|---:|---:|---:|---|
| `0x00500FBC-0x0050116A` | `run_liveness_dataflow` | 431 | 2 | 5 | `Liveness` / `PostLiveness` strings |
| `0x0051C208-0x0051C3B7` | `propagateconstants` | 432 | 4 | 12 | self-identifying trace string |
| `0x0053EADE-0x005437D3` | `loop_unroll` | 19,682 | 1 | 87 | `LOOPUNROLL>>>>` / `<<<<LOOPUNROLL` |
| `0x00545735-0x0054619F` | `dooptimize` | 2,667 | 1 | 24 | optimizer top-level trace; calls `treepeep`, constant propagation, etc. |
| `0x0054C4A7-0x0054CD7E` | `SIMD_vectorize` | 2,264 | 1 | 26 | before/start/after SIMD strings |
| `0x005522D5-0x00552434` | `find_loop_invariants` | 352 | 2 | 6 | self-identifying trace |
| `0x005558F2-0x00555A73` | `possible_induction_var` | 386 | 2 | 11 | self-identifying trace |
| `0x00557560-0x0055770D` | `check_possible_alias` | 430 | 1 | 9 | alias trace strings |
| `0x00568597-0x0056870E` | `object_motion` | 376 | 2 | 10 | `Before ObjectMotion` / `objectmotion` |
| `0x00589E83-0x0058B87A` | `substitute_driver` | 6,648 | 1 | 74 | before/after/resubstitute traces |
| `0x005CB7E0-0x005CBAD6` | `treepeep` | 759 | 3 | 10 | tree-peephole option/trace strings |
| `0x0066B178-0x0066BC30` | `dflow_vn_forward` | 2,745 | 2 | 33 | `DFLOW-VN-FWD` traces |
| `0x0066FAD9-0x0066FDEE` | `schedule_pass_1` | 790 | 2 | 15 | called in pre/post allocation scheduling |
| `0x006747DE-0x0067538D` | `branches_and_post_alloc` | 2,992 | 1 | 49 | branch cleanup plus post-allocation scheduling |
| `0x0069BF55-0x0069C296` | `register_allocation_core` | 834 | 5 | 15 | `register allocation` timer + target virtual dispatch |
| `0x006A0B1D-0x006A0E05` | `makeproc` | 745 | 1 | 23 | `makeproc` trace/timer |
| `0x006A51DD-0x006A527C` | `pre_alloc_scheduling` | 160 | 1 | 5 | explicit pre-allocation scheduling wrapper |
| `0x006AC8EB-0x006ACA14` | `fixup_driver` | 298 | 1 | 5 | called immediately after allocation core |
| `0x006ACA15-0x006ACE62` | `backend_dataflow_peephole` | 1,102 | 1 | 7 | calls VN apply and peephole2 |
| `0x006ACE63-0x006ACFA4` | `branch_optimize_driver` | 322 | 1 | 8 | calls branch/post-alloc pass |
| `0x006AD8D8-0x006ADF1B` | `independent_optimize` | 1,604 | 1 | 39 | calls `dooptimize` and independent transforms |
| `0x006ADF1C-0x006AE05B` | `allocate_registers` | 320 | 1 | 12 | RA wrapper/orchestrator |
| `0x006AE05C-0x006AE38A` | `codewrite` | 815 | 1 | 13 | final code emission stage |
| `0x006AE504-0x006AE5C8` | `codegen` | 197 | 3 | 13 | top-level backend sequence |
| `0x006D07E7-0x006D083C` | `peephole_pass_1` | 86 | 4 | 3 | peephole phase 1 |
| `0x006D183D-0x006D25FD` | `peephole_pass_2` | 3,521 | 4 | 40 | `peephole2` string |
| `0x006EF6CB-0x006EFBBF` | `optimize_tail_calls` | 1,269 | 2 | 23 | tail-call traces/options |
| `0x0071661C-0x00716859` | `spill_candidate` | 574 | 2 | 13 | `SPILL OLD` diagnostics |
| `0x0071BC67-0x0071C812` | `allocate_variable` | 2,988 | 3 | 25 | allocator neighborhood |
| `0x00739E6A-0x0073A362` | `schedule_pass_2` | 1,273 | 1 | 11 | list-scheduling diagnostics, per-block scoring |
| `0x0073A363-0x0073A67C` | `schedule_pass_3` | 794 | 2 | 10 | alternate list scheduler path |
| `0x0074C01C-0x0074C4C2` | `coalesce_stage` | 1,191 | 1 | 21 | `COALESCE stage` trace |
| `0x0074C6E1-0x0074C880` | `spill_stage` | 416 | 1 | 12 | `SPILL stage` trace |
| `0x0074C881-0x0074CDE4` | `FUN_0074C881` (RA coalesce/spill fixpoint driver) | 1,380 | 2 | 20 | directly calls both previous stages in a bounded retry loop |
| `0x0076EF82-0x0076FD2D` | `dflow_vn_forward_apply` | 3,500 | 4 | 29 | `DFLOW-VN-FWD: Begin Apply phase` |

The descriptive name for `0x0074C881` is deliberately kept out of `labels.tsv` for now; the role is clear from the decompilation but there is not yet an original-symbol/name string proving the exact historical identifier.

## Verified optimizer/backend orchestration

The central backend chain is visible directly in the decompilation of `codegen` at `0x006AE504`:

```text
codegen
  -> independent_optimize      0x006AD8D8
  -> makeproc                  0x006A0B1D
  -> allocate_registers        0x006ADF1C
  -> codewrite                 0x006AE05C
```

`codegen` only enters `makeproc -> allocate_registers -> codewrite` when the independent-optimization path returns success.  This makes `0x006AE504` the best backend top-level breakpoint/anchor for future dynamic tracing.

`allocate_registers` at `0x006ADF1C` is the next important orchestration point.  Its decompilation performs setup, optionally splits 64-bit variables, calls `register_allocation_core`, and then, for nonempty code, runs:

```text
register_allocation_core       0x0069BF55
fixup_driver                   0x006AC8EB
backend_dataflow_peephole      0x006ACA15
branch_optimize_driver         0x006ACE63
```

`backend_dataflow_peephole` directly calls `dflow_vn_forward_apply` and `peephole_pass_2`.  `branch_optimize_driver` directly calls `branches_and_post_alloc` (`0x006747DE`).

The post-allocation branch pass is also the scheduling switchboard.  Near the end of `0x006747DE`, it chooses either:

- `schedule_pass_1`, optionally followed by `schedule_pass_2`, or
- `schedule_pass_3`

depending on compiler globals/options.  `pre_alloc_scheduling` at `0x006A51DD` has the same primary choice between `schedule_pass_1` and `schedule_pass_3`.  This proves that the same scheduler families can run before and after allocation, while pass 2 is a post-allocation refinement path.

`schedule_pass_2` prints `List scheduling` diagnostics, walks each basic block, computes two resource/cost values, compares them using a ratio/threshold, and asks a target virtual method to rewrite the scheduled block.  `schedule_pass_3` also walks blocks but delegates the main scheduling operation to `FUN_00737790` before invoking the same target-side rewrite slot.  The target scheduler object is held through `DAT_00CE2320`; its vtable is queried before either pass proceeds.

The register-allocation neighborhood has an explicit iterative coalesce/spill engine.  `FUN_0074C881` calls `coalesce_stage` (`0x0074C01C`), a second allocator transform at `0x0074C4F7`, then `spill_stage` (`0x0074C6E1`) when needed.  The loop is capped at 200 iterations and has diagnostics for `MAX REORDER LOOP`, `MAX VAR SPILLS`, and `MAX VAR REORDER`.  This is a strong anchor for reconstructing the interference/coalescing policy: the graph data structures and spill decisions sit immediately around `0x0074Bxxx-0x0074CDxx`.

## Independent optimizer cluster

The middle-end/independent optimizer is concentrated around `0x0050xxxx-0x0058xxxx`, with `dooptimize` (`0x00545735`) as a central dispatcher.  High-confidence named neighbors include constant propagation, loop unrolling, SIMD vectorization, invariant discovery, induction recognition, alias checks, object motion, substitution, and tree peephole.  The direct callgraph confirms `independent_optimize` (`0x006AD8D8`) calls `dooptimize`.

Useful string anchors:

| String VA | Text | Function/xref evidence |
|---:|---|---|
| `0x00AD1C06` | `LOOPUNROLL>>>>` | xref `0x0053EBA2` in `loop_unroll` |
| `0x00AD1CF0` | `<<<<LOOPUNROLL` | xref `0x005437BC` in `loop_unroll` |
| `0x00AD1D7A` | `dooptimize` | xrefs inside `0x00545735` |
| `0x00AD2461` | `Starting SIMD_vectorize` | xref `0x0054C5DE` |
| `0x00AD2D41` | `find_loop_invariants` | xref in `0x005522D5` |
| `0x00AD34F6` | `possible_induction_var` | multiple xrefs in `0x005558F2` |
| `0x00AD3BA0` | `check_possible_alias(): checkalias: expr` | xref in `0x00557560` |
| `0x00AD50C4` | `objectmotion` | xrefs in `0x00568597` |
| `0x00ADDBA0` | `BEFORE SUBSTITUT` | xref in `0x00589E83` |

The executable also carries hundreds of internal feature names, including `loopunrolltwice`, `SIMD_vectorizer`, `allocregs_with_movebias`, `allocregs_directdatadep`, `coalesce_and_substitute`, `check_condcode_liveness`, `lame_liveness_split`, `better_graph_alloc_coalesce`, `dataflow_pass1`, `dataflow_postpeep2`, `dataflow_pass3`, `auto_SIMD_vectorizer`, `ppc_vectorizer11/13/15/20/21`, `espresso_peepholes`, and many debug/dump toggles.  `analysis/manual/internal_option_ids.tsv` and `analysis/ghidra/out/compiler_string_xrefs.tsv` are the better bulk sources; do not copy these names into function labels unless there is a code xref or callgraph proof.

## PowerPC-specific lowering / peephole fingerprints

The earliest code range contains unmistakable machine-specific transformations.  Examples:

- `0x00402FA8`: `DFLOW-RB-BKWD` transforms, including `DEL RLWIMI`
- `0x004044B4`: forward `SHIFT0` and other dataflow rewrites
- `0x0043FD5F`, `0x0043FE7A`, `0x00440657`, `0x00443822`: `__RLWIMI` paths
- `0x0045FC7D`: `OLD/NEW RLWIMI*` plus `NEW TAILCALL` diagnostics
- `0x0047C4A1`: `rlwimi` transformation
- `0x0066B178` and `0x0076EF82`: later value-numbering forward dataflow/apply phases
- `0x0075976D-0x0076E139`: numerous `DFLOW-RB-*` machine rewrites (load-immediate, extend, shifts, arithmetic NOPs, constant branches)

For Wii U matching work, these are better initial targets than frontend parsing code because they directly encode the instruction-selection/peephole choices that determine emitted PowerPC sequences.

## Scheduler and analyzer class/name registries

The binary contains compiler-specific class/pass name tables separate from ordinary MSVC RTTI.  Ghidra sees the string pointer references in `.data`; the repeated record shapes are useful anchors even though the exact GHS internal registry structure is not yet typed.

| Name | String VA | Data pointer reference |
|---|---:|---:|
| `SubstituteVariantsVisitor` | `0x00ACD2A8` | `0x00ACD058` |
| `LivenessDf` | `0x00ACF3C3` | `0x00ACF6E4` |
| `PostLivenessDf` | `0x00ACF3CE` | `0x00ACF6F4` |
| `AliasAnalyzer` | `0x00AFD938` | `0x00AFF0D0` |
| `TimeAccurateAliasAnalyzer` | `0x00AFD946` | `0x00AFF0E0` |
| `BooleanAccurateAliasAnalyzer` | `0x00AFDA80` | `0x00AFF0F0` |
| `g4_resource_scheduler` | `0x00AC5468` | `0x00AC5964` |
| `ppc970_resource_scheduler` | `0x00AC547E` | `0x00AC5974` |
| `ame_resource_scheduler` | `0x00AC5498` | `0x00AC5984` |
| `list_scheduler` | `0x00B0B7FF` | `0x00B0C0E8` |
| `resource_model_scheduler` | `0x00B0B80E` | `0x00B0C0F8` |
| `compat_list_scheduler` | `0x00B0B7DC` | `0x00B0C108` |
| `ls_window_scheduler` | `0x00B0B7C8` | `0x00B0C118` |
| `spill_variable_set::listener` | `0x00B0D6F1` | `0x00B0D6A4` |

The PowerPC resource-scheduler records are especially useful for Espresso work: `g4`, `ppc970`, and `ame` are adjacent and point into a common table neighborhood around `0x00AC58E4-0x00AC598C`, which itself contains code pointers in the `0x00738xxx-0x007399xx` scheduler region.  This is a promising path to recover the processor resource model used by the list scheduler.

### PowerPC resource-scheduler virtual tables

The `g4_resource_scheduler`, `ppc970_resource_scheduler`, and `ame_resource_scheduler` registrations can be followed one step further.  Each 16-byte class-registration record is referenced immediately before a custom GHS virtual-table body.  Taking the word after that registration pointer as slot 0 yields 13 consecutive 8-byte pairs `(this_adjust, code_pointer)` for each class; all recovered `this_adjust` values are zero.  This matches the indirect-call shape Ghidra emits elsewhere in this compiler, where it loads the adjustment from the first word of a slot and the callee from the second word.  The table-body addresses below are therefore strong vptr candidates, although the exact constructor/store that installs them has not yet been identified.

| scheduler | registration | vptr | base descriptor | slots |
|---|---:|---:|---:|---:|
| `g4_resource_scheduler` | `0x00AC5960` | `0x00AC5818` | `0x00AC5450` | 13 |
| `ppc970_resource_scheduler` | `0x00AC5970` | `0x00AC5888` | `0x00AC5458` | 13 |
| `ame_resource_scheduler` | `0x00AC5980` | `0x00AC58F8` | `0x00AC5460` | 13 |

The three tables share most of their implementation.  Their slot map is:

| slot | G4 | PPC970 | AME | evidence / role clue |
|---:|---:|---:|---:|---|
| 0 | `0x00486B90` | `0x00486B90` | `0x0048A852` | G4/PPC970 return true; AME additionally initializes scheduler limits |
| 1 | `0x00487F47` | `0x00488266` | `0x0048AF87` | G4/AME tail-call common `0x0073950F`; PPC970 performs list preprocessing first |
| 2 | `0x007387CF` | same | same | common scheduler setup/dispatch |
| 3 | `0x00738DE5` | same | same | common resource-model state update |
| 4 | `0x00738772` | same | same | common resource-state walk |
| 5 | `0x00738D12` | same | same | common scheduling/resource loop |
| 6 | `0x00739097` | same | same | large common scheduling loop; emits resource/vtime diagnostics |
| 7 | `0x00739679` | same | same | prints resource requirements |
| 8 | `0x00739659` | same | same | tiny common hook |
| 9 | `0x00739AE2` | same | same | scheduling decisions/statistics dump |
| 10 | `0x00739824` | same | same | scheduled-instruction/resource dump |
| 11 | `0x00486CBC` | `0x00487FF2` | `0x0048A91C` | **target-specific opcode -> resource/latency assignment** |
| 12 | `0x007399DD` | same | same | resource-instance dump |

Slot 11 is the strongest processor-specific scheduling anchor found so far.  The G4 implementation is a large opcode switch that fills per-instruction resource fields; PPC970 derives instruction classes through `0x004883C3` and a local capacity table around `0x00AC54B8`; AME uses its own instruction classifier (`0x0049DFEF`) and target-specific latency/resource values.  For Espresso matching, comparing which of these resource models the compiler instantiates and how slot 11 classifies the emitted instruction stream should reveal scheduling choices that cannot be inferred from the generic list-scheduler code alone.

`analysis/manual/extract_static_anchors.py` now reconstructs these tables automatically into `resource_scheduler_vtables` in `analysis/manual/ecomppc_static_anchors.json`.

## Real MSVC RTTI and vtables

There are only four conventional MSVC RTTI type-descriptor strings in this image.  They are runtime-library classes, not the optimizer visitor/scheduler classes above:

| Class/type descriptor | TypeDescriptor VA | Complete object locator | vftable | Recovered vtable entries |
|---|---:|---:|---:|---|
| `std::bad_alloc` (`.?AVbad_alloc@std@@`) | `0x00BD5194` | `0x00ABCB64` | `0x00AB9EE4` | `0x00A9F61F`, `0x00AAE871` |
| `std::exception` (`.?AVexception@std@@`) | `0x00BD51B0` | `0x00ABCBE4` | `0x00ABC2EC` | `0x00AAE87E`, `0x00AAE871` |
| `type_info` (`.?AVtype_info@@`) | `0x00BD5FC4` | `0x00ABCBF8` | `0x00ABC30C` | `0x00AAE8AF` (`scalar_deleting_destructor`) |
| `std::bad_exception` (`.?AVbad_exception@std@@`) | `0x00BD5FE0` | `0x00ABCC40` | `0x00ABC338` | `0x00AAE965`, `0x00AAE871` |

Ghidra's Microsoft analyzer also creates the expected `RTTI_Complete_Object_Locator`, `RTTI_Class_Hierarchy_Descriptor`, `RTTI_Base_Class_Array`, and base-class-descriptor labels in `0x00ABCB64-0x00ABCC70`.  This limited RTTI set is itself useful: most compiler C++ class identity must be recovered through the custom name/descriptor tables and virtual-call shapes rather than expecting normal MSVC RTTI for every optimizer class.

## Source/module layout from embedded paths

Embedded source-path xrefs give a surprisingly strong module map.  The ranges below are xref-containing functions, so they are anchors rather than guaranteed complete object-file boundaries.

### Backend/shared code

- `0x005092B9-0x0050946D`: `src/compilers/indep/indcod.cc`
- `0x0059C820`: `src/shared/genout.c`
- `0x005A5634-0x005A56FF`: `src/shared/indgen.c`
- `0x005AEC8F-0x005AF67B`: `src/shared/indtime.c`
- `0x005B9771`: `src/compilers/indep/ghspascal.cc`
- `0x0061AC7B`: `src/compilers/indep/indstatic.cc`
- `0x00667482`: `src/compilers/indep/inddfvnadvisor.cc`
- `0x00721F03-0x00726220`: `src/compilers/indep/indcase.cc`
- `0x0074281B`: `src/compilers/indep/indopc.cc`
- `0x0073B751-0x00790B2E`: EASE assembler parser/field/target/disassembler neighborhoods
- `0x0079B5C2-0x007A0B02`: `src/shared/indinst/*`
- `0x007A0ED0-0x007A11CF`: `src/shared/indoutputgen.cc`

### EDG frontend

The EDG frontend becomes dense starting around `0x007A3870` and remains contiguous through roughly `0x00991457`.  Strong per-source anchors include:

- `attribute.c`: `0x007A3870-0x007A75BE`
- `class_decl.c`: `0x007A7DCB-0x007BBAEF`
- `cmd_line.c`: `0x007BBF40-0x007C6B9F`
- declaration/statement/expression modules across `0x007CD1E4-0x00841C98`
- `il.c`: `0x0085C20F-0x00872711`
- `inline.c`: `0x0089DD61-0x008A0606`
- `lexical.c`: `0x008A3FA2-0x008B9415`
- lowering modules: `0x008C46ED-0x008EB80C`
- `overload.c`: `0x008FE2C3-0x00911142`
- `statements.c`: `0x009230C9-0x0092CF9D`
- `symbol_tbl.c`: `0x00933981-0x0093FE3E`
- `templates.c`: `0x00947845-0x00963385`
- `types.c`: `0x009725DF-0x0097EEED`
- GHS EDG pragmas/DSP/asmsym: `0x0097F4B5-0x00991457`

The GHS backend bridge then reappears clearly:

- `src/compilers/edg/ghs_be.cc`: `0x009A47F1-0x009B958B`
- `src/compilers/edg/ghs_debug.c`: `0x009BB230-0x009BF8A6`
- `src/compilers/edg/ghs_tdeh.cc`: `0x009C0153-0x009C1356`

This split is useful for prioritization: matching-code investigations should usually start in the independent/backend ranges (`0x0040xxxx-0x007A11CF`) and the `ghs_be.cc` bridge, while EDG parsing/semantic code is mostly irrelevant unless a source-language construct is being lowered differently before the independent IR.

## High-value next reverse-engineering targets

1. **Espresso scheduler selection and resource model.**  The `g4`/`ppc970`/`ame` tables and their overrides are now recovered.  Trace which registration/table is selected for `-cpu=espresso`, then type the `DAT_00CE2320` scheduler object and name the common virtual slots used for availability/cost and final schedule emission.  The bare `espresso` strings found so far sit in data/option tables and do not by themselves prove the active resource model.
2. **Graph allocator core** around `0x0074Bxxx-0x0074CDxx`.  Type the variable/interference objects used by `coalesce_stage`, `spill_stage`, and `FUN_0074C881`; then follow the callers into `register_allocation_core`.  This is likely the highest-value cluster for matching register choices/spill behavior.
3. **Backend target vtable** referenced via `DAT_00BDB584`.  Known virtual offsets appear at least at `+0x394`, `+0x484`, `+0x524`, `+0x67C`, `+0x834` in the recovered passes.  Naming that interface would connect target-specific Espresso behavior to generic passes.
4. **PowerPC dataflow/peephole families** around `0x00402xxx-0x0047xxxx` and `0x00759xxx-0x0076FDxx`.  The RLWIMI/rotate-mask and constant-branch rewrites are direct fingerprints for matching output.
5. **`ghs_be.cc` bridge** at `0x009A47F1-0x009B958B`.  Use its source-path xrefs and caller relationships to recover the handoff from EDG IL to GHS independent IR; this is the natural place to determine which source constructs change the optimizer's initial graph.

## Reproduction commands

Export the current Ghidra program/function/symbol inventory without rerunning analysis:

```sh
tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless \
  analysis/ghidra/project GHS5322 \
  -process ecomppc.exe -noanalysis \
  -scriptPath analysis/ghidra/scripts \
  -postScript DumpProgramInventory.java analysis/ghidra/out/inventory
```

Rebuild the PE/import/RTTI/registry anchor JSON:

```sh
python3 analysis/manual/extract_static_anchors.py \
  ghs5.3.22/bin/ecomppc.exe \
  --functions analysis/ghidra/out/inventory/functions.tsv \
  -o analysis/manual/ecomppc_static_anchors.json
```

Existing high-value supporting outputs:

- `analysis/ghidra/labels.tsv` — curated pass labels
- `analysis/ghidra/out/labeled_callgraph.tsv` — callers/callees of labeled passes
- `analysis/ghidra/out/compiler_string_xrefs.tsv` — optimizer/backend/source-path string xrefs
- `analysis/ghidra/out/all_string_xrefs.tsv` — broad string/data references
- `analysis/ghidra/out/keypasses/` — decompilations of curated pass functions
- `analysis/manual/ecomppc_static_anchors.json` — reproducible PE/import/RTTI/registry anchors
- `analysis/ghidra/out/inventory/functions.tsv` — all 21,953 recovered function boundaries
