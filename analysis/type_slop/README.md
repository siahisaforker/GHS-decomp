# GHS `ecomppc.exe` type slop

This directory turns the recovered GHS custom class registry and custom
vtables into broad, confidence-tagged type hypotheses for the stripped
`ecomppc.exe`.  The goal is coverage: give decompilation agents class families,
virtual slot identities, likely object initializers, and nearby class-associated
helpers without pretending every generated name is ground truth.

The source data is the 428-record registry in
`analysis/worker3_static_map/ghs_registry.tsv` and the 253 recovered custom
vtables in `analysis/worker3_static_map/ghs_vtables.tsv`.  The registry exposes
353 explicit primary-base links.  The vtables contain 2,605 slot entries and
about 1,550 unique executable targets.

## Regeneration

Run these commands from the repository root.  The first command reuses the
existing analyzed Ghidra project and does no new analysis pass.

```sh
tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless \
  analysis/ghidra/project GHS5322 \
  -process ecomppc.exe -noanalysis \
  -scriptPath analysis/type_slop \
  -postScript DumpVtableRefs.java \
  analysis/worker3_static_map/ghs_vtables.tsv \
  analysis/type_slop/vtable_xrefs.tsv

python3 analysis/type_slop/normalize_vptr_refs.py
python3 analysis/type_slop/build_type_slop.py
python3 analysis/type_slop/validate_type_slop.py
```

`DumpVtableRefs.java` asks Ghidra for references to both the table header and
the first slot-pair address.  In this executable, the useful object stores are
to the **table header**.  For example, `FUN_00424ceb` installs `0x00abf65c`
for `backend_t`; the first `(this_adjust, code)` pair starts later at
`0x00abf664`.  `normalize_vptr_refs.py` keeps only memory-write instructions,
which currently reduces 1,012 raw table references to 420 store-backed refs in
136 functions.

`build_type_slop.py` never changes the Ghidra database.  It emits proposals
only.

## Canonical outputs

`class_groups.tsv` groups registry records by the root reached through the
explicit primary-base link.  The current map has 75 roots/families.

`hierarchy.tsv` is one row per registry record, with primary base, family,
depth, recovered vtable address, and slot count.

`virtual_slots.tsv` is one row per recovered virtual entry.  Each row has a
stable family-level semantic key such as `backend_dataflow.slot_029`, the
concrete class, target function, relation to the immediate base
(`inherited`, `override`, or `root_or_new`), and a proposed function label.

`function_hypotheses.tsv` is the main propagation product.  It currently has
2,938 function hypotheses: 1 curated constructor anchor, 1,552 direct virtual
methods, 119 constructor/destructor-like vptr writers, and 1,266 callgraph
neighbors associated with a class family.  The graph-only labels are capped
at lower confidence so generic helpers do not become fake class methods just
because many typed routines call them.

`backend_hierarchy.tsv` and `backend_slots.tsv` isolate the backend family for
fast use by PowerPC backend work.  `type_map.json` contains the same canonical
map in machine-readable form plus summary counts.

## Extended slop snapshots

The directory also preserves a denser parallel propagation snapshot:

- `class_hierarchy.tsv`
- `virtual_methods.tsv`
- `shared_slot_semantics.tsv`
- `ctor_dtor_hypotheses.tsv`
- `function_class_hypotheses.tsv`
- `fun_labels.tsv`
- `backend_t_hierarchy.tsv`
- `type_slop.json` and `summary.json`

These tables intentionally make more aggressive guesses.  They record 2,605
slot/class rows, 441 constructor/destructor/vptr-reference hypotheses, 11,979
class/function associations, and 2,916 proposed labels for default `FUN_`
functions.  Use their confidence and evidence columns when importing or
triaging them.  They are useful slop, not a promise that the proposed C++ name
is exact.

## Concrete hierarchy and object anchors

The backend hierarchy is now structural rather than an address-local guess:

```text
backend_dataflow  0x00b0e82c  vtable 0x00b0e53c   28 slots
  backend_basetype   0x00afc4e0  vtable 0x00afbb90  262 slots
    backend_basetype2  0x00b0b784  vtable 0x00b0af4c  262 slots
      backend_t          0x00abfe94  vtable 0x00abf65c  262 slots
```

The extended slot comparison says `backend_basetype2` keeps 109 slots from
`backend_basetype` and overrides 153; `backend_t` keeps 94 slots from
`backend_basetype2` and overrides 168.  `backend_basetype` expands the
28-slot `backend_dataflow` surface to 262 slots, with 234 newly introduced
positions.

High-value vtable-store anchors include:

| function | class evidence | installed table | hypothesis |
| --- | --- | ---: | --- |
| `0x00424ceb` | `backend_t` | `0x00abf65c` | constructor, curated prior anchor |
| `0x00486b99` | `g4_resource_scheduler` | `0x00ac5810` | constructor-like |
| `0x00487f60` | `ppc970_resource_scheduler` | `0x00ac5880` | constructor-like |
| `0x0048a79c` | `ame_resource_scheduler` | `0x00ac58f0` | constructor-like |
| `0x0071df17` | `alloc_table` then `alloc_table_hash` | `0x00b0a4d8`, `0x00b0a550` | derived construction chain |
| `0x0071df90` | `alloc_table` then `alloc_table_btree` | `0x00b0a4d8`, `0x00b0a578` | derived construction chain |
| `0x0071e0e0` | `alloc_table` then `alloc_table_bcl` | `0x00b0a4d8`, `0x00b0a5a0` | derived construction chain |

The scheduler family also comes directly from the registry:

```text
list_scheduler
  resource_model_scheduler
    g4_resource_scheduler
    ppc970_resource_scheduler
    ame_resource_scheduler
  compat_list_scheduler

ws_interface
  ls_window_scheduler
```

The allocation-table family is:

```text
alloc_table
  alloc_table_hash
  alloc_table_btree
  alloc_table_bcl
```

In the extended pass, slot 0 is marked only as a low-confidence lifecycle /
destructor candidate unless other evidence supports it.  For the allocation
table children, `0x0071dfdd`, `0x0071e0a4`, and `0x0071e19f` both appear in
slot 0 and write their own class table, so they are stronger
destructor-or-virtual-reinitialization candidates.

## Confidence interpretation

Direct registry ancestry and direct vtable membership are the strongest
evidence.  Single-class store-backed table writes are also strong initializer
evidence, while functions that write several related tables are treated as
base/derived construction or lifecycle candidates.  A shared virtual target
keeps its family slot identity even when the exact method name is unknown.

Callgraph propagation is deliberately weaker.  It is meant to answer “this
`FUN_` is probably part of the same class subsystem” and should not be read as
proof of a `this` parameter.  Repeated `std::*` registry records also occur in
several compiler modules, so record VA and family ID are safer keys than class
name alone.

No executable bytes are copied into these maps.
