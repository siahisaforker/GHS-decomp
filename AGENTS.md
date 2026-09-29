# AI OPERATING NOTES

This repository is an AI-facing reverse-engineering scratch corpus for Green Hills C/C++ 5.3.22 Nintendo (`ecomppc.exe`).

Optimize for machine consumption, coverage, evidence retention, and resumability. Do not spend time making the tree aesthetically clean.

## Canonical identity

Use function entry VA as the primary key everywhere.

- canonical text form: 8 lowercase hex digits, no `0x` prefix, e.g. `00422ff4`
- when preserving an original artifact that already uses another form, keep it but add/derive the canonical form
- never identify a function only by a guessed name

## Evidence discipline

Keep facts and hypotheses separate.

A useful row/object should preserve:

- `va`: canonical function VA
- `raw_name`: current Ghidra/original recovered name
- `proposed_name`: inferred semantic name, nullable
- `confidence`: numeric 0.0..1.0
- `evidence_kinds`: list/string set such as `direct_string_xref`, `source_path_xref`, `callgraph`, `vtable_slot`, `registry`, `decompiled_body`, `oracle`, `manual`
- `evidence_refs`: concrete addresses, file paths, strings, slot offsets, option IDs, or other machine-followable references
- `module`: inferred original source/module/class bucket
- `module_confidence`: 0.0..1.0
- `provenance`: generating script/artifact

Do not turn a weak inference into a fact just because several agents repeat it.

## Preferred artifacts

Prefer, in order:

1. JSONL: one self-contained function/hypothesis object per line
2. TSV: large flat tables keyed by VA
3. JSON: manifests, schemas, summaries, dependency graphs
4. Markdown: only for compact orientation or explanations that cannot fit cleanly in structured data

Large, ugly, redundant structured files are acceptable. Human-oriented polish is not a goal.

## Current global corpus

The canonical inventory contains 21,953 Ghidra-recognized functions. `analysis/full_decomp/coverage.tsv` is the current per-function coverage table and `analysis/full_decomp/callgraph.tsv` is the full directed callgraph export. Batch lists under `analysis/full_decomp/batch_lists/` cover every function that lacked a C export when the batch plan was generated.

Useful evidence sources include:

- `analysis/full_decomp/coverage.tsv`
- `analysis/full_decomp/callgraph.tsv`
- `analysis/prime/source_file_function_map.tsv`
- `analysis/ghidra/labels.tsv`
- `analysis/worker3_static_map/ghs_registry.tsv`
- `analysis/worker3_static_map/ghs_vtables.tsv`
- `analysis/backend_map/target_vtable.csv`
- `analysis/backend_map/target_options.csv`
- `analysis/oracle/` for black-box compiler fingerprints

## AI-slop rule

Breadth beats polish. Preserve hypotheses with confidence/evidence instead of deleting them. Generate names/types/modules aggressively, but keep their confidence and provenance explicit so later agents can override them safely.
