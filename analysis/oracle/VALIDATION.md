# Validation record

Host validation was performed on 2026-09-28 from the repository root.

## Runner and optimization flags

Wine is available at `/usr/bin/wine`.  `wibo` was not present on `PATH`, so
the harness currently selects Wine when `--runner auto` is used.

The driver help was queried with:

```sh
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -help
```

It documents the Green Hills optimization modes `-Omaxdebug`, `-Odebug`,
`-Ogeneral`, `-Ospeed`, and `-Ospace`.  The GCC-style spellings requested for
the oracle were then tested directly:

```sh
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -O0 -S -o out.s input.c
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -O  -S -o out.s input.c
WINEDEBUG=-all wine ghs5.3.22/bin/cxppc.exe -O2 -S -o out.s input.c
```

All three returned 0.  `cxppc.exe -#` exposes their backend expansion:

- `-O0`: no `--option=142 -O`/`-OL` optimizer selector; includes `-X3838`.
- `-O`: includes `--option=142 -O --option=87 --option=88`.
- `-O2`: includes `-X2696 --option=142 -OL -X482 --option=87 --option=88`.

For the `arith.c` probe, `-O` and `-Ogeneral` produced byte-for-byte identical
`cxppc -#` traces and identical objects:

```text
68fe78e777d82895e6a87f3dd22c4e31fbfa99feb3e6986524aac4494f4449a7  -O
68fe78e777d82895e6a87f3dd22c4e31fbfa99feb3e6986524aac4494f4449a7  -Ogeneral
```

## Full oracle run

The complete default matrix is run with:

```sh
python3 analysis/oracle/run_blackbox.py
```

The default source list comes from `analysis/oracle/corpus/manifest.json`, so
scratch probes added beside it do not silently change the matrix.  The current
manifest contains 9 C/C++ sources.  At `-O0`, `-O`, and `-O2` that is 27 runs.
Every run returned 0 for:

- the `cxppc.exe -#` backend trace;
- `cxppc.exe -S` assembly generation;
- direct object generation;
- `-noobj -keeptempfiles` compiler -> assembler generation;
- direct replay of the traced argv through `ecomppc.exe`;
- `llvm-objdump -dr` of the resulting PowerPC object.

The retained `pipeline_temp.s` files confirm that `-noobj -keeptempfiles`
keeps the compiler's assembler input.  `result.json` stores normalized assembly
hashes so the driver, retained temp, and direct `ecomppc.exe` outputs can be
compared while ignoring the driver-only command banner and compile timestamp.

One C++-specific trace detail was handled in the parser: after the wrapped
`ecomppc.exe` command, `cxppc.exe -#` may print a separate cleanup command such
as `rm -f "(null)"`.  The harness stops at the end of the first continued
command before replaying the backend argv.

The run products and exact commands are in
`analysis/oracle/runs_blackbox/<case>/<mode>/`, with the aggregate result in
`analysis/oracle/runs_blackbox/summary.json`.
