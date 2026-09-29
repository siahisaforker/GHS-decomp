# Automatic semantic-name proposals

`build_auto_names.py` generates a broad, confidence-scored naming pass for the stripped `ecomppc.exe` Ghidra database. It does **not** modify Ghidra. The output is intended for search, triage, review, and selective import after a human or later analysis pass accepts a proposal.

The generator combines the current 21,953-function inventory with direct embedded-source associations, every exported string xref, the full direct callgraph, recovered GHS class registry/vtables, existing semantic labels, the curated backend map, and all currently exported decompiler bodies. Source-module labels are propagated through two callgraph rounds only when at least two neighbors agree; a weaker address-bracketing inference is used when two nearby direct source anchors name the same original source module.

Run it from the repository root:

```sh
python3 analysis/auto_names/build_auto_names.py
python3 analysis/auto_names/validate_outputs.py
```

Outputs (AI-ingestion contract):

- `observations.jsonl`: facts/current state only: stable VA, raw label, call edges, string xrefs, vtable membership, decompiler path, and explicitly marked upstream source associations.
- `proposals.tsv`: inferred naming hypotheses, deterministic order, normalized lowercase `0x........` VA, confidence 0..1, evidence kinds/refs, raw/proposed names, callers/callees/options/strings/vtable/source fields, and provenance.
- `proposals.jsonl`: array-friendly equivalent with parsed evidence objects.
- `summary.json`: coverage/counts by confidence and proposal type.
- `summary.md`: generated high-level findings and representative proposals.
- `checkpoint.json`: exact input hashes, decompiler-export aggregate hash, generator hash, output paths, counts, and resume command.
- `schema.json`: explicit fact-vs-hypothesis contract, normalized VA format, confidence bands, and deterministic ordering contract.

Confidence describes the proposal's semantic usefulness, not certainty that the text is the compiler's original symbol. Names deliberately retain an address suffix. A class/vtable proposal such as `backend_t__vslot_181_instruction_encoder_422ff4` makes a strong structural claim but does not pretend the original source used that exact spelling. Module-only and propagated names are similarly explicit hypotheses.

The useful review thresholds are:

- `high` (`>= 0.82`): direct class/vtable structure or multiple strong independent signals.
- `medium` (`0.65..0.819`): direct source/module or strong string evidence with support.
- `speculative` (`< 0.65`): graph/address propagation, body-shape roles, or semantic-neighbor hypotheses. These are intentionally retained because the goal is high-coverage AI-assisted triage.
