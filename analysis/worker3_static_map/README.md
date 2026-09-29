# Worker 3 static map additions for `ecomppc.exe`

Target: local GHS 5.3.22 Wii U `ecomppc.exe`, SHA-256
`b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3`.

This note complements `analysis/ecomppc_static_map.md` and the Ghidra outputs. It
focuses on static facts that can be reproduced directly from the raw PE and on
the compiler's custom class/type registry.

## PE anchors

- PE32 i386 console image, image base `0x00400000`, stripped COFF/debug data.
- Entry point: RVA `0x006938ff`, VA `0x00a938ff`.
- Four sections: `.text` RVA `0x1000` size `0x6b5934`; `.rdata` RVA
  `0x6b7000` size `0x7a96`; `.data` RVA `0x6bf000` size `0x28b688`; `.sxdata`
  RVA `0x94b000` size `0x13c`.
- Import table RVA `0x006bd85c`, IAT RVA `0x006b7000`.
- 219 imports across `KERNEL32.dll` (173), `WS2_32.dll` (29), `ADVAPI32.dll`
  (10), `USER32.dll` (5), `NETAPI32.dll` (1), and `MPR.dll` (1). This is host
  runtime/licensing support; compiler optimization/code-generation logic is
  statically linked into the executable.

Ghidra's current inventory contains 21,953 recovered functions. The central
backend anchors already verified in the shared map are:

| VA | role |
|---:|---|
| `0x00545735` | `dooptimize`, high-level optimizer driver |
| `0x0066fad9` | scheduling pass 1 |
| `0x0069bf55` | register-allocation core |
| `0x006a0b1d` | `makeproc` |
| `0x006ad8d8` | independent optimizer/backend bridge |
| `0x006adf1c` | allocation wrapper |
| `0x006ae05c` | final code-write stage |
| `0x006ae504` | top-level `codegen` root |
| `0x00739e6a` | list-scheduling pass 2 |
| `0x0073a363` | alternate list-scheduling pass 3 |
| `0x0074c01c` | coalesce stage |
| `0x0074c6e1` | spill stage |

The direct backend sequence is `codegen -> independent_optimize -> makeproc ->
allocate_registers -> codewrite`; allocation then invokes the core allocator,
fixups, backend dataflow/peephole, and post-allocation branch/scheduling work.

## Custom GHS class registry

Normal MSVC RTTI is nearly useless for compiler internals here: the only four
ordinary type descriptors found are `std::bad_alloc`, `std::exception`,
`type_info`, and `std::bad_exception`. In contrast, the executable contains a
custom GHS registry with **428 valid records**. Every recovered record has the
layout:

```text
+0x00  0x00bd4990       registry sentinel / common type node
+0x04  name pointer     NUL-terminated class/type name
+0x08  tag pointer      usually in the 0x00d47xxx range
+0x0c  descriptor ptr   null or class relationship/interface metadata
```

`0x00bd4990` is the common pointer stored in every record; a record at
`0x00bd49a0` uses it and names `std::type_info`. This, together with the
descriptor/base links below, supports treating the repeated structures as GHS
runtime class descriptors rather than unrelated string tables.

`enumerate_ghs_registry.py` scans the raw PE for these records and emits all 428
entries as TSV. It also follows a repeatable inheritance encoding: a descriptor
commonly begins with `(base_record_va, 0x00160000)`. Because descriptor entries
are packed adjacently, only that first pair is decoded for each class; reading
past it would incorrectly absorb neighboring classes' descriptors.

Concrete inheritance anchors:

| derived record | derived name | descriptor | recovered base |
|---:|---|---:|---|
| `0x00ac5960` | `g4_resource_scheduler` | `0x00ac5450` | `resource_model_scheduler` (`0x00b0c0f4`) |
| `0x00ac5970` | `ppc970_resource_scheduler` | `0x00ac5458` | `resource_model_scheduler` (`0x00b0c0f4`) |
| `0x00ac5980` | `ame_resource_scheduler` | `0x00ac5460` | `resource_model_scheduler` (`0x00b0c0f4`) |
| `0x00acf6e0` | `LivenessDf` | `0x00acf238` | `InterblockDf` (`0x00acf300`) |
| `0x00acf6f0` | `PostLivenessDf` | `0x00acf240` | `InterblockDf` (`0x00acf300`) |
| `0x00aff0dc` | `TimeAccurateAliasAnalyzer` | `0x00afd130` | `AliasAnalyzer` (`0x00aff0cc`) |
| `0x00aff0ec` | `BooleanAccurateAliasAnalyzer` | `0x00afd140` | `AliasAnalyzer` (`0x00aff0cc`) |
| `0x00b0e84c` | `RBFwdDataFlow` | `0x00b0d8d8` | `IndDataFlow` (`0x00b0e83c`) |
| `0x00b0e85c` | `RBBkwdDataFlow` | `0x00b0d8e0` | `IndDataFlow` (`0x00b0e83c`) |
| `0x00b0e86c` | `RegReNameBkwdDataFlow` | `0x00b0d8e8` | `IndDataFlow` (`0x00b0e83c`) |

This fixes a small address ambiguity in earlier scratch notes: for example the
`g4_resource_scheduler` **record starts at `0x00ac5960`**; its name pointer is at
`0x00ac5964`. Likewise `list_scheduler` starts at `0x00b0c0e4` and its name
pointer is at `0x00b0c0e8`.

High-value registry families include:

- scheduler: `g4_resource_scheduler`, `ppc970_resource_scheduler`,
  `ame_resource_scheduler`, `list_scheduler`, `resource_model_scheduler`,
  `compat_list_scheduler`, `ls_window_scheduler`;
- allocation: `alloc_table`, `alloc_table_hash`, `alloc_table_btree`,
  `alloc_table_bcl`, `spill_variable_set::listener`, `register_range`,
  `register_set`, `register_implicit`, `register_list`, `register_map`;
- optimizer/dataflow: `LivenessDf`, `PostLivenessDf`, `TouchesDf`,
  `DownSafetyDf`, `UpSafetyDf`, `EarliestDf`, `DelayedDf`, `LatestDf`,
  `IsolatedDf`, `Gcse*Df`, `CopyPropDf`, `AliasAnalyzer`,
  `TimeAccurateAliasAnalyzer`, `BooleanAccurateAliasAnalyzer`,
  `RBFwdDataFlow`, `RBBkwdDataFlow`, `RegReNameBkwdDataFlow`, and
  `VNFwdDataFlow`.

One particularly useful inheritance chain reaches the concrete target backend:

```text
backend_t                 record 0x00abfe94
  -> backend_basetype2    record 0x00b0b784
     -> backend_basetype  record 0x00afc4e0
        -> backend_dataflow record 0x00b0e82c
```

`backend_t` has a **262-slot** custom vtable at vptr `0x00abf664`. Its entries include
the early PowerPC rewrite functions at `0x00402fa8` (`DFLOW-RB-BKWD`/RLWIMI
diagnostics) and `0x004044b4` (forward shift/dataflow rewrites), tying the
custom class map directly to machine-specific code generation rather than only
generic compiler infrastructure.

The registry is therefore a durable way to recover class families and
inheritance even where compiler-internal MSVC RTTI is missing. For virtual-call
work, start from the registry descriptor, then inspect pointer tables adjacent
to it and correlate executable targets with
`analysis/ghidra/out/inventory/functions.tsv`.

## Custom vtables

`enumerate_ghs_vtables.py` follows a second repeated GHS runtime pattern. A
high-confidence custom vtable has a two-word header `[0, class_record_va]`
followed by `(this_adjust, code_pointer)` pairs; the object vptr points at the
first pair. The scanner requires at least two consecutive slots whose code
pointers land in `.text`. It recovers **253 candidate tables** from the 428
registry records in this image.

The three processor resource schedulers are especially clean anchors:

| class | record | vptr | slots |
|---|---:|---:|---:|
| `g4_resource_scheduler` | `0x00ac5960` | `0x00ac5818` | 13 |
| `ppc970_resource_scheduler` | `0x00ac5970` | `0x00ac5888` | 13 |
| `ame_resource_scheduler` | `0x00ac5980` | `0x00ac58f8` | 13 |

Their common generic scheduling slots point into the `0x007387xx-0x00739axx`
region. Slot 11 is processor-specific: G4 uses `0x00486cbc`, PPC970 uses
`0x00487ff2`, and AME uses `0x0048a91c`. That is the strongest static hook for
reconstructing target-specific resource/latency classification.

Two additional analysis families now have direct virtual-method anchors:

| class | vptr | slots |
|---|---:|---|
| `LivenessDf` | `0x00acf6a8` | `0x00500b9f`, `0x00500cd7` |
| `PostLivenessDf` | `0x00acf6c0` | `0x00500d3f`, `0x00500d44` |
| `AliasAnalyzer` | `0x00afef64` | `0x005cf400`, `0x005cf409` |
| `TimeAccurateAliasAnalyzer` | `0x00afef7c` | `0x005cf40e`, `0x005cf451` |
| `BooleanAccurateAliasAnalyzer` | `0x00afef94` | `0x005db3f1`, `0x005db4b8` |

All ten addresses above are exact Ghidra-recovered function entries. These are
good next decompilation targets for reconstructing the semantic differences
between ordinary/time-accurate/boolean-accurate alias analysis and the two
liveness variants.

## Reproduction

Generate the full registry table:

```sh
python3 analysis/worker3_static_map/enumerate_ghs_registry.py \
  ghs5.3.22/bin/ecomppc.exe \
  -o analysis/worker3_static_map/ghs_registry.tsv
```

Filter one family on stdout, for example:

```sh
python3 analysis/worker3_static_map/enumerate_ghs_registry.py \
  ghs5.3.22/bin/ecomppc.exe --category scheduler
```

Generate high-confidence custom vtables:

```sh
python3 analysis/worker3_static_map/enumerate_ghs_vtables.py \
  ghs5.3.22/bin/ecomppc.exe \
  -o analysis/worker3_static_map/ghs_vtables.tsv
```

The script only reads the local compiler binary and emits metadata; it does not
copy or redistribute executable contents.
