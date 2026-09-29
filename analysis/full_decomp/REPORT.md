# Full semantic decomp coverage

Inventory denominator: **21,953 Ghidra functions**. The headless callgraph export has **83,510 directed edges**; **82,753** connect two functions in the 21,953-function inventory and are used for locality clustering.

## Measured coverage

| signal | functions / records | function coverage |
|---|---:|---:|
| any non-`FUN_` semantic name | 670 | 3.05% |
| curated `USER_DEFINED` semantic name | 34 | 0.15% |
| direct embedded-source association (>=80% confidence) | 1,736 | 7.91% |
| existing Ghidra decompiled body | 2,821 | 12.85% |
| unique function appearing in recovered vtable slot(s) | 1,552 | 7.07% |
| direct/inferred/vtable module cluster | 6,994 | 31.86% |
| any core semantic/structural evidence | 4,270 | 19.45% |

Recovered class metadata contains **428 registry records**, **253 vtables**, and **2,605 vtable slot references**. These are structural artifacts; they are not counted as completed function semantics unless they identify a function slot.

## Semantic completion estimate

The evidence-weighted current estimate is **~7.5%** of a full semantic decomp, with a reasonable **±2 percentage-point** uncertainty band. Source-file and module associations identify locality, while only a small number of functions have human-curated behavior names/types. The raw structural footprint is higher (19.45%), but treating that as semantic completion would overstate progress.

The scoring proxy gives 20% credit for an existing decompiled body, 25% for a direct source-module association, 10% for a conservative inferred module, 35% for a curated semantic name (15% for another recovered semantic symbol), and 10% for vtable membership. Scores are capped at 100% per function. This makes mechanically exported C useful but insufficient by itself.

Module locality is currently direct-source for **1,736** functions, address-inferred for **3,111**, callgraph-inferred for **222**, corroborated by both for **467**, and vtable-only for **1,458**. **14,959** remain without a module assignment.

Subsystem percentages below are estimates over the currently classified cohorts, not claims that those cohorts exhaust the subsystem. The large `unclustered` cohort is kept explicit instead of forcing weak address-only subsystem assignments.

## Subsystem estimates

| wave | functions | decompiled | direct source | vtable funcs | clustered | semantic estimate | remaining C exports |
|---|---:|---:|---:|---:|---:|---:|---:|
| `backend_target` | 461 | 461 | 52 | 388 | 461 | **33.73%** | 0 |
| `optimizer` | 438 | 438 | 25 | 351 | 404 | **32.80%** | 0 |
| `frontend_bridge` | 324 | 324 | 108 | 0 | 324 | **35.00%** | 0 |
| `frontend` | 4,992 | 1,555 | 1,551 | 0 | 4,992 | **20.90%** | 3,437 |
| `runtime_support` | 739 | 0 | 0 | 136 | 136 | **14.08%** | 739 |
| `unclustered` | 14,999 | 43 | 0 | 677 | 677 | **0.54%** | 14,956 |

## Remaining gaps and batch plan

**19,132** functions still lack an exported Ghidra C body. **17,683** lack all four core signals (semantic name, decompiled body, direct source association, vtable membership).

`batches.json` contains **361 batches** (maximum 96 functions each). Existing decompiled functions are excluded. Ordering is backend target → optimizer → frontend bridge → frontend → runtime support → unclustered. Within a likely module, breadth-first traversal of the induced callgraph keeps callers/callees together; seed selection favors semantic names, source/vtable evidence, graph centrality, and larger bodies.

`batch_manifest.tsv` is the compact scheduling view. It records the strongest cross-batch outgoing dependencies and incoming neighbors so adjacent batches can be scheduled together when a decompilation needs caller/callee context.

Direct source paths are high-confidence anchors. Inferred module labels require either matching source anchors on both address sides within 64 KiB, at least two direct-source callgraph neighbors with >=75% agreement, or both. Vtable-only groupings are explicitly marked as lower-confidence structural locality.
