# Reconstructed backend pipeline

This is the current high-level flow recovered from Ghidra call relationships and embedded pass strings.

```text
codegen @ 0x006ae504
  |
  +-- independent_optimize @ 0x006ad8d8
  |     |
  |     +-- dooptimize @ 0x00545735
  |            |
  |            +-- propagateconstants @ 0x0051c208
  |            +-- treepeep          @ 0x005cb7e0
  |                   |
  |                   +-- object_motion @ 0x00568597
  |
  +-- makeproc @ 0x006a0b1d
  |
  +-- allocate_registers @ 0x006adf1c
  |     |
  |     +-- register_allocation_core @ 0x0069bf55
  |     +-- fixup_driver             @ 0x006ac8eb
  |     |      +-- register_allocation_core (conditional re-run)
  |     |
  |     +-- backend_dataflow_peephole @ 0x006aca15
  |     |      +-- dflow_vn_forward_apply @ 0x0076ef82
  |     |      +-- peephole_pass_2       @ 0x006d183d
  |     |             +-- peephole_pass_1      @ 0x006d07e7
  |     |             +-- optimize_tail_calls  @ 0x006ef6cb
  |     |
  |     +-- branch_optimize_driver @ 0x006ace63
  |            +-- branches_and_post_alloc @ 0x006747de
  |                   +-- schedule_pass_1 @ 0x0066fad9
  |                   +-- schedule_pass_2 @ 0x00739e6a
  |                   +-- schedule_pass_3 @ 0x0073a363
  |
  +-- codewrite @ 0x006ae05c
```

Other recovered anchors:

| address | recovered role |
|---|---|
| `0x00500fbc` | `run_liveness_dataflow` |
| `0x0053eade` | `loop_unroll` |
| `0x0054c4a7` | `SIMD_vectorize` |
| `0x005522d5` | `find_loop_invariants` |
| `0x005558f2` | `possible_induction_var` |
| `0x00557560` | `check_possible_alias` |
| `0x00568597` | `object_motion` |
| `0x00589e83` | substitution driver |
| `0x0066b178` | forward dataflow/value-numbering stage |
| `0x006a51dd` | pre-allocation scheduling |
| `0x0071661c` | spill-candidate logic |
| `0x0071bc67` | variable allocation |
| `0x0074c01c` | coalescing stage |
| `0x0074c6e1` | spill stage |

These are reverse-engineering labels, not original symbols. Confidence varies by label; direct pass-name strings and strong call-graph placement get the highest confidence.
