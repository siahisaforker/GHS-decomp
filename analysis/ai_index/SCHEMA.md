# AI ingestion schema

All new per-function datasets should converge on these field names when applicable.

| field | type | meaning |
|---|---|---|
| `va` | string | canonical entry VA, 8 lowercase hex digits |
| `end_va` | string/null | canonical exclusive/end address if known |
| `size` | integer/null | function body size in bytes |
| `raw_name` | string/null | current Ghidra/recovered name |
| `name_source` | string/null | DEFAULT/ANALYSIS/USER_DEFINED/etc. |
| `proposed_name` | string/null | AI/inference semantic name |
| `role` | string/null | short semantic role independent of exact name |
| `confidence` | float | confidence in proposal, 0..1 |
| `module` | string/null | likely original source/module/class bucket |
| `module_confidence` | float/null | 0..1 |
| `source_file` | string/null | embedded source-path assignment when available |
| `source_confidence` | float/null | 0..1 |
| `class_names` | array/string-set | registry/vtable-associated classes |
| `vtable_slots` | array/string-set | exact table/slot references |
| `callers` | array | strongest caller VAs/names |
| `callees` | array | strongest callee VAs/names |
| `strings` | array | directly referenced strings or strongest string evidence |
| `options` | array | compiler option IDs/names/global addresses involved |
| `evidence_kinds` | array | normalized evidence categories |
| `evidence_refs` | array | concrete machine-followable evidence references |
| `decompile_path` | string/null | local/generated pseudocode path |
| `provenance` | array/string | scripts/artifacts that produced the row |
| `status` | string | e.g. `observed`, `inferred`, `hypothesis`, `needs_review` |

Do not require all fields in every artifact. Stable VA identity + explicit confidence/provenance are the minimum contract for inferred data.
