# Wii U / PowerPC emitter seam

This directory is a focused static map of the Wii U-specific PowerPC output
path in `ghs5.3.22/bin/ecomppc.exe` (SHA-256
`b28a092e01f818aa6183dfdbbd40623920d672dc6d37376c0da4fb6084d2f7b3`).
It starts from target-vtable method offset `+0x5e4 -> 0x00422ff4` and follows
the finalized instruction stream into textual assembly or ELF object output.

The main correction to the earlier broad backend map is semantic:
`0x00422ff4` is **not the raw PPC instruction emitter**.  It is a late
procedure metadata pass that computes a 96-bit register-change mask.  The
actual per-instruction output split is `0x0047f1a6`; binary PPC encoding is
`0x00497b18`, backed by the opcode registry initialized at `0x00491eb5`.

## The +0x5e4 callback: register-change-mask finalization

`codewrite @ 0x006ae05c` invokes target slot `+0x5e4` once the procedure
has a finalized instruction list.  The target table resolves that method to
`0x00422ff4` (2417 bytes).

The recovered partitions are in `finalizer_partitions.csv` and
`finalizer_regions.csv`:

| VA range | Meaning |
| --- | --- |
| `0x00422ff4..0x0042301d` | optional `ppc_ep_rpx_tnt` cleanup through `0x00422f2e` |
| `0x0042301e..0x00423059` | master `useregchgmask` and procedure eligibility checks |
| `0x0042305a..0x00423091` | `ada95` suppression path |
| `0x00423092..0x00423152` | clear three working masks, preserve prior bits, walk finalized instructions |
| `0x00423153..0x00423832` | conditionally add r3/r4 to the GPR-class mask |
| `0x00423833..0x0042395f` | shift/merge the three masks into procedure state and set valid bit 0x80 |

The working masks are six 16-bit words each (96 bits):

- `0x00bdb560`
- `0x00bdb56c`
- `0x00bdb578`

The helper semantics are concrete:

- `0x00406399`: fill six 16-bit words.
- `0x00405d8a`: six-word AND.
- `0x00405dc1`: six-word OR.
- `0x00405df8`: 96-bit left shift over six 16-bit words.
- `0x00422e2d`: instruction/operand walker callback.
- `0x0042226d`: classify visited target registers into the three masks.

The final mask is stored at target procedure state `+0xb0`; target procedure
state byte `+0x59`, bit `0x80`, is the validity flag.

The special augmentation block marks two consecutive target registers.  The
PowerPC target initializer sets the relevant base to 3, so this becomes r3 and
r4.  It runs only when `ajo1 == 0 && (codefactor || linkxda)`.

Exact option gates are recorded in `option_gates.csv`:

| option | ID | byte VA | use in 0x00422ff4 |
| --- | ---: | ---: | --- |
| `ppc_ep_rpx_tnt` | 1800 | `0x00c40d56` | pre-cleanup |
| `useregchgmask` | 1326 | `0x00c40b7c` | master enable |
| `ada95` | 1373 | `0x00c40bab` | special-procedure suppression |
| `ajo1` | 385 | `0x00c407cf` | must be clear for r3/r4 augmentation |
| `codefactor` | 2942 | `0x00c411cc` | enables r3/r4 augmentation |
| `linkxda` | 3077 | `0x00c41253` | enables r3/r4 augmentation |

The very large blocks in the middle of the decompile that mention
`invalid bitset<N> position` are range-error scaffolding from the C++
bitset implementation, not additional PPC emission stages.

## Actual instruction output boundary

`0x004f5247` walks the final instruction records and calls
`0x0047f1a6` for each instruction.  `0x0047f1a6` is the concrete
text-vs-object boundary:

- `obj` option ID 75, byte `0x00c40699 == 0`: print textual PowerPC
  assembly.
- `obj != 0`: call `0x00497b18` to encode/write binary object code.

The text path uses `0x0047e00e` as the recursive PPC operand and relocation
syntax printer.  Its recovered strings include `%hiadj`, `%highera`,
`%highesta`, `%pidlo`, `%pidhiadj`, TLS syntax, SDA offsets, and other
PowerPC assembler forms.  This directly matches the syntax visible in the
`-S` oracle fixtures.

`0x0074281b`, tied by an embedded source path to
`src/compilers/indep/indopc.cc`, is a generic opcode-interface dispatcher.
It asks a target-specific encoder to fill a 4096-byte opdata buffer.  In text
mode it can fall back to `0x0047e00e`; in object mode a failed target
encoding is treated as invalid.  Its only direct callers recovered here are
`0x007438b4` and `0x0074520f`.

## PPC opcode descriptor database

`0x00476da3` initializes the PowerPC target and calls `0x00491eb5`.
`0x00491eb5` registers 572 fixed opcode descriptors with
`0x00491dc0`.  Each descriptor is 16 bytes:

| offset | field |
| --- | --- |
| `+0x0` | mnemonic pointer |
| `+0x4` | 32-bit base instruction word |
| `+0x8` | encoding/operand format ID |
| `+0xc` | hash-chain next pointer |

Descriptors are inserted into a 255-bucket hash table at `0x00bdae18`.
`opcode_table.csv` is the full extracted table.

There are 35 paired-single / quantized paired-single descriptors in the fixed
table.  Examples:

| mnemonic | format | base word |
| --- | ---: | ---: |
| `psq_l` | `0xa3` | `0xe0000000` |
| `psq_lx` | `0xa4` | `0x1000000c` |
| `psq_st` | `0xa3` | `0xf0000000` |
| `ps_add` | `0x23` | `0x1000002a` |
| `ps_madd` | `0x72` | `0x1000003a` |
| `ps_merge10` | `0x23` | `0x100004a0` |

The `analysis/oracle/_ps_probe/ps.s` fixture emits
`ps_merge10 f31,f31,f31`, matching the exact descriptor above.

## Binary encoding and object emission

`0x00497b18` is the concrete per-instruction PowerPC binary encoder.  It
looks up the descriptor through `0x004969e6`, dispatches on the format ID,
packs operands into the base word, emits relocations when needed, and writes a
four-byte instruction.

Recovered field packers are listed in `encoding_forms.csv`.  The
Wii U/Gekko-specific quantized paired-single forms are especially useful:

- `0x00496041`, format `0xa3`: FR@21:5, RA@16:5, displacement@0:12,
  W@15:1, I@12:3.
- `0x004960f6`, format `0xa4`: FR@21:5, RA@16:5, RB@11:5,
  W@10:1, I@7:3.

Other recovered packers cover D, I-branch, B-branch, XL-branch, X,
rotate/mask, and five-field forms.

`0x004e5aad` is the 32-bit word sink.  In object mode it writes two 16-bit
halves; option `bigendian` (ID 78, byte `0x00c4069c`) controls their
order.  In text/non-object mode it prints the four bytes as a `.byte` style
fallback and advances the current section location by four bytes.

`0x004e76f6` creates object relocation records.  Before classifying the
operand it calls target vtable slot `+0x7b4`, making that callback the next
target-specific relocation seam worth recovering.

The object oracle confirms the encoder path rather than only the mnemonic
table.  `oracle_correlation.csv` records, among others:

- `lfsx`: observed `0x7da4042e`, base `0x7c00042e`.
- `stfsx`: observed `0x7c03052e`, base `0x7c00052e`.
- `fmadds`: observed `0xec0d603a`, base `0xec00003a`.
- `blr`: observed `0x4e800020`, identical to its fixed base word.

The oracle object is ELF32 big-endian PowerPC, consistent with the
`bigendian` word-writer behavior.

## Espresso target defaults and late peepholes

`0x00476da3` also sets a large block of PowerPC defaults and explicitly
enables these Espresso transforms:

`espresso_basic_ps_opt`, `espresso_loadstore_opt`,
`espresso_peepholes`, `espresso_combine_merge`,
`espresso_combine_load`, `espresso_combine_store`, `espresso_fsplat`,
`espresso_cmp`, `espresso_ps_pre`, and
`espresso_ps_structinreg`.

The exact bytes are in `target_default_options.csv`.  The target initializer
does not set the top-level `espresso` ID 4649 byte in this routine, and does
not set `espresso_merge_epilogue` ID 4727 here; those are configured
elsewhere.

The late Espresso peephole dispatcher is `0x0045fc7d`.  The recovered
ordered helpers are in `espresso_peephole_order.csv`:

1. `0x0045f169` — combine store
2. `0x0045ea8d` — combine merge
3. `0x0045ec4a` — combine load
4. `0x0045f7e5` — fsplat
5. `0x0045f976` — compare combine

Their embedded diagnostics (`PS COM MERGE1`, `PS LOAD NEW`,
`PS ST OLD ...`, `NEW PS FSPLAT`, `PS CMP NEW`) give unusually strong
semantic anchors.

## Nearby target callbacks

`function_map.csv` contains confidence-scored roles and callgraph/string/
option/vtable evidence.  The most useful methods adjacent to `+0x5e4` are:

- `+0x5cc -> 0x00423965`: 4/8-byte operand-size selector.
- `+0x5d4 -> 0x00423991`: 16/32-byte special operand-size selector.
- `+0x5ec -> 0x00423ce7`: extended-asm legal register mask.
- `+0x604 -> 0x00423e2d`: I/U/X extended-asm constraint classifier.
- `+0x624 -> 0x00423c13`: register-class table selector with
  AltiVec/e500 gates.
- `+0x62c -> 0x00423aa1`: instruction predicate influenced by
  `ppc_isel`, `ppc_fsel`, and the SIMD vectorizer.
- `+0x64c -> 0x00423caf`: target register-number table lookup.
- `+0x674 -> 0x004242c0`: textual PPC64 traceback byte emission.
- `+0x834 -> 0x00424c57`: branch-merge helper.

## Reproduction

The main generated data can be rebuilt locally:

```sh
python3 analysis/ppc_emitter/build_output_map.py
python3 analysis/ppc_emitter/build_map.py
python3 analysis/ppc_emitter/build_ai_manifest.py
```

Focused decompiles use the existing Ghidra project:

```sh
tools/ghidra_12.0.4_PUBLIC/support/analyzeHeadless \
  analysis/ghidra/project GHS5322 \
  -process ecomppc.exe -noanalysis \
  -scriptPath analysis/ghidra/scripts \
  -postScript DecompileAddresses.java \
  analysis/ppc_emitter/focus_addresses.tsv \
  analysis/ppc_emitter/decompiled
```

The generators verify the compiler SHA-256 and expected table sizes before
writing output.  `observed_facts.jsonl`, `hypotheses.jsonl`, and
`checkpoint.json` are compact machine-readable handoff files for another
worker.

The next highest-value seam is the target relocation callback at vtable slot
`+0x7b4` called by `0x004e76f6`, followed by completing every remaining
format-ID case in `0x00497b18`.
