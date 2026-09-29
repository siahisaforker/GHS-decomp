# auto_names summary

- schema_version: 1
- functions_total: 21953
- unnamed_functions: 21283
- proposal_count: 9838
- high: 2988
- medium: 1829
- speculative: 5021
- observed_function_rows: 21953

## proposal_kind_counts

```json
{
  "class_vmethod": 1258,
  "curated_backend_map": 7,
  "module_role": 5153,
  "named_neighbor": 204,
  "role_only": 634,
  "string_semantic": 1929,
  "weak_evidence": 653
}
```

## evidence_kind_counts

```json
{
  "address_bracket": 2622,
  "backend_map": 7,
  "callgraph_round_1": 890,
  "callgraph_round_2": 1023,
  "decompiled_body": 1562,
  "direct_source": 1736,
  "direct_string": 3399,
  "semantic_neighbor": 587,
  "vtable": 1552
}
```

## resume

`python3 analysis/auto_names/build_auto_names.py`

Facts and hypotheses are separated: `observations.jsonl` contains function/xref/vtable/callgraph observations; `proposals.tsv` and `proposals.jsonl` contain inferred semantic names/roles.
