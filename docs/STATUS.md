# Status

## Target

- Green Hills C/C++ PowerPC compiler
- `C-POWERPC 5.3.22 RELEASE VERSION`
- `MULTI v5.3.22 Nintendo`
- Wii U / Espresso target
- primary compiler executable: `ecomppc.exe`
- driver: `cxppc.exe`
- assembler: `asppc.exe`

The target is a stripped 32-bit x86 PE. It does not ship usable normal function symbols or a useful embedded PDB/debug directory, so names in this repository are recovered from behavior, strings, call relationships, and source-file breadcrumbs.

## Static-analysis findings

The compiler leaks a large amount of internal vocabulary despite being stripped. Observed pass/debug strings include:

- `dooptimize`
- `propagateconstants`
- `SIMD_vectorize`
- loop unrolling and induction-variable analysis
- alias analysis
- liveness/dataflow/value numbering
- object motion and substitution
- scheduling
- register allocation / spilling / coalescing
- peephole optimization
- branch optimization
- tail-call optimization

Embedded source paths expose substantial parts of the original layout, including:

- `src/edg/src/*`
- `src/compilers/edg/ghs_be.cc`
- `src/compilers/edg/ghs_debug.c`
- `src/compilers/edg/ghs_tdeh.cc`
- `src/compilers/indep/*`
- `src/shared/indinst/*`
- `src/asm/ease/*`
- `src/roach/*`

A first source-path mapping pass associated roughly **1,700 functions** with embedded source-file references. This is a module breadcrumb map, not proof of original function names.

## Compiler oracle

The real compiler runs under Wine.

`cxppc -#` exposes the internal stage invocation, including the `ecomppc.exe` command line. Using the driver with temporary-output preservation lets us retain the exact assembly produced by `ecomppc` before `asppc` assembles it.

The current corpus covers or is expanding toward:

- arithmetic and signedness
- shifts / masks / rotate-mask idioms
- bitfields
- branches and dense/sparse switches
- loops and unrolling
- constant multiplication/division
- float / double
- structs and ABI cases
- many-argument calls
- global loads/stores
- narrow integer extension
- C++ inline/virtual cases
- paired-single candidates

One early fingerprint: optimized bit extraction/insertion is lowered into `rlwinm` + `rlwimi` patterns, which is exactly the kind of signature useful to a matching-decomp agent.

## Next research targets

1. strengthen the backend pass graph with more direct evidence;
2. map internal option strings and global bytes to individual pass gates;
3. characterize register allocation, spill/coalesce decisions, and scheduling;
4. build deterministic source -> GHS assembly fingerprints across optimization modes;
5. teach a matching-decomp loop to diagnose diffs in compiler terms instead of blindly mutating source.
