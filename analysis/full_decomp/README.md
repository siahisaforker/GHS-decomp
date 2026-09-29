# Full semantic-decomp coverage tooling

This directory measures the current reverse-engineering state of
`ecomppc.exe` against the complete 21,953-function Ghidra inventory and turns
the remaining functions into locality-aware headless decompilation batches.

Regenerate the full internal callgraph from the existing Ghidra project:

```sh
tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless \
  analysis/ghidra/project GHS5322 \
  -process ecomppc.exe -noanalysis \
  -scriptPath analysis/ghidra/scripts \
  -postScript DumpAllCallGraph.java analysis/full_decomp/callgraph.tsv
```

Rebuild coverage and prioritized manifests:

```sh
python3 analysis/full_decomp/build_coverage.py
```

Primary outputs:

- `REPORT.md`: human-readable coverage and semantic-completion estimate.
- `coverage.json`: machine-readable totals, scoring rubric, subsystem estimates.
- `coverage.tsv`: one row for every Ghidra function with all evidence fields.
- `callgraph.tsv`: complete headless callgraph export.
- `batches.json`: prioritized batch metadata and cross-batch dependencies.
- `batch_manifest.tsv`: compact scheduling view.
- `batch_lists/*.tsv`: address/name lists accepted by `DecompileAddresses.java`.

Preview the generated export commands:

```sh
python3 analysis/full_decomp/export_batches.py --dry-run --limit 2
```

Export one batch:

```sh
python3 analysis/full_decomp/export_batches.py --batch 0008_backend_target
```

Export the first backend-target batch, or all matching batches when `--limit`
is omitted:

```sh
python3 analysis/full_decomp/export_batches.py --wave backend_target --limit 1
```

The exporter reuses the existing `GHS5322` project and runs with `-noanalysis`;
it does not re-import or re-analyze the compiler binary.
