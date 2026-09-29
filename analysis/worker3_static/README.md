# ecomppc scheduler/allocator static anchors

This directory extends the general `ecomppc.exe` map with the custom GHS
scheduler class registry and callback tables.  The target is the local
GHS 5.3.22 Wii U `ecomppc.exe`; no binary data is redistributed here.

Run:

```sh
python3 analysis/worker3_static/registry_map.py \
  ghs5.3.22/bin/ecomppc.exe \
  --functions analysis/ghidra/out/inventory/functions.tsv \
  -o analysis/worker3_static/registry_map.json
```

The scheduler families use a custom 16-byte registration record rather than
normal MSVC RTTI.  For these records, `+0x04` is the class-name pointer and
`+0x0c` is a descriptor pointer.  The descriptor begins with the base class's
registration-record pointer.  This gives the following concrete hierarchy:

```text
list_scheduler                         record 0x00B0C0E4
  +-- resource_model_scheduler         record 0x00B0C0F4
  |     +-- g4_resource_scheduler      record 0x00AC5960
  |     +-- ppc970_resource_scheduler  record 0x00AC5970
  |     +-- ame_resource_scheduler     record 0x00AC5980
  +-- compat_list_scheduler            record 0x00B0C104

ws_interface                           record 0x00B0B7B8
  +-- ls_window_scheduler              record 0x00B0C114
```

The three PowerPC resource schedulers all point at the
`resource_model_scheduler` record through descriptors at `0x00AC5450`,
`0x00AC5458`, and `0x00AC5460`.  Their callback tables start at
`0x00AC5814`, `0x00AC5884`, and `0x00AC58F4`.  Those tables contain direct
code pointers into the PowerPC/backend scheduler region, including the dense
`0x007387CF-0x00739AE2` family, plus a few target-specific helpers in the
`0x0048xxxx` range.

The runtime resource-scheduler selector is `FUN_0048AFA0` at
`0x0048AFA0-0x0048AFFB`.  It writes the selected object to `DAT_00CE2320`:

| Condition | Constructor/init | Installed callback table | Interpretation |
|---|---:|---:|---|
| option byte `0x00C409E0` set | `0x00487F60` | object `+0x3C = 0x00AC5880` -> callbacks `0x00AC5884` | `ppc970_resource_scheduler` |
| otherwise `DAT_00BE8B30 != 0` | `0x0048A79C` | object `+0x3C = 0x00AC58F0` -> callbacks `0x00AC58F4` | `ame_resource_scheduler` |
| fallthrough | `0x00486B99` | object `+0x3C = 0x00AC5810` -> callbacks `0x00AC5814` | `g4_resource_scheduler` |

The first branch is independently identified: `analysis/backend_map/target_options.csv`
maps internal option ID 914, `ppc970`, to byte `0x00C409E0`.  The AME branch
is structurally certain from the constructor's installed `0x00AC58F0` table;
the exact user-facing setting which populates `DAT_00BE8B30` still needs a
focused option-parser trace.  The binary does contain the string `ame-config=`.

This makes `0x0048AFA0` a particularly useful breakpoint for determining
which scheduling model Espresso actually selects for a given compiler command
line.  With the package's default `-cpu=espresso`, logging this function and
the resulting `DAT_00CE2320` value would settle the active model directly.

The generic scheduler callback tables are anchored by registration-record
backreferences near `0x00B0BF44-0x00B0C0E4`.  The most useful recovered
entries include `0x007374DB`, `0x00737736`, `0x00737790`, `0x00737C92`,
`0x00738528`, `0x007385F8`, `0x0073950F`, and `0x0073A7F7`.  The already
identified `schedule_pass_3` at `0x0073A363` calls `0x00737790` directly,
which ties the class-table cluster to the live scheduling path rather than
leaving it as an isolated string/table guess.

Other high-value anchors verified while building this map:

| Subsystem | Address | Evidence |
|---|---:|---|
| top-level backend | `0x006AE504` | `codegen` orchestrator |
| independent optimizer | `0x006AD8D8` | calls `dooptimize` |
| machine-procedure build | `0x006A0B1D` | `makeproc` stage |
| register-allocation wrapper | `0x006ADF1C` | invokes RA core then fixup/dataflow/branches |
| register-allocation core | `0x0069BF55` | allocation timer + target callback |
| coalesce stage | `0x0074C01C` | `COALESCE stage` diagnostic |
| spill stage | `0x0074C6E1` | `SPILL stage` diagnostic |
| coalesce/spill retry loop | `0x0074C881` | bounded loop with max-spill/reorder diagnostics |
| pre-allocation scheduler | `0x006A51DD` | scheduling wrapper |
| scheduler pass 1 | `0x0066FAD9` | before/after scheduling diagnostics |
| scheduler pass 2 | `0x00739E6A` | PPC750/PPC7450/resource scheduling path |
| scheduler pass 3 | `0x0073A363` | list-scheduler path, calls `0x00737790` |
| final emission | `0x006AE05C` | `codewrite` stage |

The backend target object is held through runtime global `DAT_00BDB584`.
Its concrete initializer is `FUN_00424CEB` (`0x00424CEB-0x00424E2C`): it
allocates `0x251C` bytes, calls `0x005BAC03`, installs interface/table pointers,
and stores the resulting object to `DAT_00BDB584` at instruction `0x00424E25`.
This is the best early breakpoint for recovering the target-interface layout.

Recovered virtual/interface slots include:

| Offset | Static use |
|---:|---|
| `+0x01C` / `+0x06C` | backend dataflow/value-numbering setup/query |
| `+0x154` | `dooptimize` target hook |
| `+0x25C`, `+0x264`, `+0x26C` | late peephole target hooks |
| `+0x29C`, `+0x2A4` | loop-unroll legality/lowering hooks |
| `+0x2D4` | tree peephole hook |
| `+0x394` | block schedule installation from both list-scheduler paths |
| `+0x42C` | register-variable allocation decision |
| `+0x484` | post-allocation expand-code hook |
| `+0x524` | register-allocation completion hook |
| `+0x5AC` | SIMD-vectorizer target hook |
| `+0x67C` | instruction/dead-code predicate |
| `+0x6A4` | loop-unroll target capability query |
| `+0x834` | late branch helper |

`DAT_00CE2320` is the active scheduler object used by `schedule_pass_2` and
`schedule_pass_3`.  Both runtime globals live in the `.data` zero-fill tail,
so their writers are more useful static anchors than the on-disk bytes.
