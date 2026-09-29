# Embedded-source → function map

Parsed **1736 source-file/function associations** across **84 embedded source paths** and **1736 functions**. Associations come from direct references to embedded source-path strings; they are strong module breadcrumbs, not proof of exact original function names.

## Largest source-file clusters

| source file | funcs | xrefs | address span |
|---|---:|---:|---|
| `src/edg/src/il.c` | 116 | 211 | `0x0085c20f–0x00872711` |
| `src/edg/src/templates.c` | 114 | 200 | `0x00947845–0x00963385` |
| `src/edg/src/expr.c` | 94 | 163 | `0x0080bac0–0x00830048` |
| `src/edg/src/lower_il.c` | 90 | 133 | `0x008ce293–0x008dd5c9` |
| `src/edg/src/lower_init.c` | 72 | 139 | `0x008dd8be–0x008eb80c` |
| `src/compilers/edg/ghs_be.cc` | 64 | 149 | `0x009a47f1–0x009b958b` |
| `src/edg/src/class_decl.c` | 59 | 98 | `0x007a7dcb–0x007bbaef` |
| `src/edg/src/exprutil.c` | 52 | 70 | `0x00830f3e–0x00841c98` |
| `src/edg/src/overload.c` | 52 | 89 | `0x008fe2c3–0x00911142` |
| `src/edg/src/symbol_tbl.c` | 51 | 87 | `0x00933981–0x0093fe3e` |
| `src/edg/src/lexical.c` | 50 | 89 | `0x008a3fa2–0x008b9415` |
| `src/edg/src/trans_corresp.c` | 49 | 63 | `0x00968234–0x009715d5` |
| `src/edg/src/decls.c` | 48 | 112 | `0x007ed1c8–0x00803cb1` |
| `src/edg/src/statements.c` | 41 | 83 | `0x009230c9–0x0092cf9d` |
| `src/compilers/edg/ghs_debug.c` | 38 | 59 | `0x009bb230–0x009bf8a6` |
| `src/edg/src/scope_stk.c` | 37 | 59 | `0x0091b373–0x00921f7f` |
| `src/edg/src/lower_c99.c` | 36 | 55 | `0x008c46ed–0x008c844b` |
| `src/edg/src/pragma_ghs.c` | 36 | 48 | `0x0097f4b5–0x00988909` |
| `src/edg/src/lower_name.c` | 32 | 61 | `0x008eb8ea–0x008f0713` |
| `src/edg/src/types.c` | 30 | 46 | `0x009725df–0x0097eeed` |
| `src/edg/src/decl_inits.c` | 29 | 79 | `0x007cd1e4–0x007d5794` |
| `src/edg/src/decl_spec.c` | 27 | 59 | `0x007d5e70–0x007e40b9` |
| `src/edg/src/folding.c` | 27 | 58 | `0x0084a8a8–0x0085306b` |
| `src/edg/src/trans_copy.c` | 27 | 84 | `0x009637e0–0x00967c08` |
| `src/edg/src/il_to_str.c` | 25 | 50 | `0x008806fe–0x00886211` |
| `src/edg/src/dsp_c.c` | 24 | 45 | `0x00989462–0x0098c9bc` |
| `src/edg/src/lookup.c` | 24 | 28 | `0x008bc253–0x008c463b` |
| `src/edg/src/lower_eh.c` | 22 | 32 | `0x008c86e1–0x008cda64` |
| `src/edg/src/macro.c` | 19 | 31 | `0x008f0dc0–0x008f9fba` |
| `src/edg/src/attribute.c` | 18 | 30 | `0x007a3870–0x007a75be` |
| `src/edg/src/pragma_asmsym.c` | 17 | 23 | `0x0098f2dd–0x00991457` |
| `src/edg/src/host_envir.c` | 16 | 21 | `0x0085714e–0x0085ac38` |
| `src/edg/src/extasm.c` | 15 | 17 | `0x008422cc–0x0084413c` |
| `src/edg/src/il_walk.c` | 15 | 17 | `0x0088dc14–0x0089d88d` |
| `src/edg/src/declarator.c` | 14 | 29 | `0x007e42d0–0x007ec430` |
| `src/edg/src/error.c` | 14 | 18 | `0x00806410–0x0080b6af` |
| `src/edg/src/inline.c` | 14 | 27 | `0x0089dd61–0x008a0606` |
| `src/edg/src/cmd_line.c` | 13 | 45 | `0x007bbf40–0x007c6b9f` |
| `src/edg/src/pch.c` | 13 | 17 | `0x009114c0–0x009140c8` |
| `src/edg/src/func_def.c` | 12 | 35 | `0x008535c1–0x00856b1e` |

## Subtree totals

| subtree | unique function associations |
|---|---:|
| `src/edg/src` | 1551 |
| `src/compilers/edg` | 108 |
| `src/shared/indinst` | 24 |
| `src/compilers/indep` | 20 |
| `src/asm/ease` | 16 |
| `src/shared/indtime.c` | 6 |
| `src/shared/indoutputgen.cc` | 6 |
| `src/shared/indgen.c` | 2 |
| `src/shared/genout.c` | 1 |
| `src/shared/dsmangle.c` | 1 |
| `src/shared/gsr` | 1 |

## High-confidence single-file assignments

1736 functions have ≥80% of their embedded-source xrefs pointing at one source file.

| address | current name | likely source | refs | confidence |
|---|---|---|---:|---:|
| `0048ce9f` | `FUN_0048ce9f` | `src/compilers/indep/ghspascal.h` | 31/31 | 100% |
| `004a8d79` | `FUN_004a8d79` | `src/compilers/indep/ghspascal.h` | 2/2 | 100% |
| `005092b9` | `FUN_005092b9` | `src/compilers/indep/indcod.cc` | 1/1 | 100% |
| `0050946d` | `FUN_0050946d` | `src/compilers/indep/indcod.cc` | 1/1 | 100% |
| `005693bf` | `FUN_005693bf` | `src/compilers/indep/ghspascal.h` | 2/2 | 100% |
| `0059c820` | `FUN_0059c820` | `src/shared/genout.c` | 3/3 | 100% |
| `005a5634` | `FUN_005a5634` | `src/shared/indgen.c` | 2/2 | 100% |
| `005a56ff` | `FUN_005a56ff` | `src/shared/indgen.c` | 2/2 | 100% |
| `005aec8f` | `FUN_005aec8f` | `src/shared/indtime.c` | 1/1 | 100% |
| `005aee45` | `FUN_005aee45` | `src/shared/indtime.c` | 3/3 | 100% |
| `005aef5c` | `FUN_005aef5c` | `src/shared/indtime.c` | 1/1 | 100% |
| `005af210` | `FUN_005af210` | `src/shared/indtime.c` | 1/1 | 100% |
| `005af430` | `FUN_005af430` | `src/shared/indtime.c` | 1/1 | 100% |
| `005af67b` | `FUN_005af67b` | `src/shared/indtime.c` | 1/1 | 100% |
| `005b9771` | `FUN_005b9771` | `src/compilers/indep/ghspascal.cc` | 2/2 | 100% |
| `0061ac7b` | `FUN_0061ac7b` | `src/compilers/indep/indstatic.cc` | 1/1 | 100% |
| `0062d2d0` | `FUN_0062d2d0` | `src/shared/dsmangle.c` | 1/1 | 100% |
| `00667482` | `FUN_00667482` | `src/compilers/indep/inddfvnadvisor.cc` | 1/1 | 100% |
| `0066e8a1` | `FUN_0066e8a1` | `src/compilers/indep/ghspascal.h` | 2/2 | 100% |
| `0066f237` | `FUN_0066f237` | `src/compilers/indep/ghspascal.h` | 1/1 | 100% |
| `00721f03` | `FUN_00721f03` | `src/compilers/indep/indcase.cc` | 1/1 | 100% |
| `0072217c` | `FUN_0072217c` | `src/compilers/indep/indcase.cc` | 1/1 | 100% |
| `00722aa8` | `FUN_00722aa8` | `src/compilers/indep/indcase.cc` | 1/1 | 100% |
| `00724b9f` | `FUN_00724b9f` | `src/compilers/indep/indcase.cc` | 1/1 | 100% |
| `007250db` | `FUN_007250db` | `src/compilers/indep/indcase.cc` | 2/2 | 100% |
| `007253cc` | `FUN_007253cc` | `src/compilers/indep/indcase.cc` | 3/3 | 100% |
| `00725f1c` | `FUN_00725f1c` | `src/compilers/indep/indcase.cc` | 3/3 | 100% |
| `00726220` | `FUN_00726220` | `src/compilers/indep/indcase.cc` | 2/2 | 100% |
| `0073b751` | `FUN_0073b751` | `src/asm/ease/easeparsers.h` | 1/1 | 100% |
| `0073b7ac` | `FUN_0073b7ac` | `src/asm/ease/easeparsers.h` | 1/1 | 100% |
| `0074281b` | `FUN_0074281b` | `src/compilers/indep/indopc.cc` | 1/1 | 100% |
| `00786515` | `FUN_00786515` | `src/asm/ease/easefield.cc` | 2/2 | 100% |
| `00786589` | `FUN_00786589` | `src/asm/ease/easefield.cc` | 1/1 | 100% |
| `00786837` | `FUN_00786837` | `src/asm/ease/easefield.cc` | 2/2 | 100% |
| `00786a31` | `FUN_00786a31` | `src/asm/ease/easefield.cc` | 1/1 | 100% |
| `00787175` | `FUN_00787175` | `src/asm/ease/easefield.cc` | 1/1 | 100% |
| `007874c6` | `FUN_007874c6` | `src/asm/ease/easefield.cc` | 1/1 | 100% |
| `0078a732` | `FUN_0078a732` | `src/asm/ease/easeparsers.h` | 1/1 | 100% |
| `0078a78d` | `FUN_0078a78d` | `src/asm/ease/easeparsers.h` | 1/1 | 100% |
| `0078dcfb` | `FUN_0078dcfb` | `src/asm/ease/easetarg.cc` | 1/1 | 100% |
| `0078fd46` | `FUN_0078fd46` | `src/asm/ease/easetarg.cc` | 1/1 | 100% |
| `00790b2e` | `FUN_00790b2e` | `src/asm/ease/easetarg.cc` | 2/2 | 100% |
| `00795d77` | `FUN_00795d77` | `src/asm/ease/easedis.h` | 1/1 | 100% |
| `007972fd` | `FUN_007972fd` | `src/asm/ease/easedis.cc` | 1/1 | 100% |
| `0079ab66` | `FUN_0079ab66` | `src/asm/ease/easedis.cc` | 2/2 | 100% |
| `0079b5c2` | `FUN_0079b5c2` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079b669` | `FUN_0079b669` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079b73a` | `FUN_0079b73a` | `src/shared/indinst/indinstparsers.cc` | 2/2 | 100% |
| `0079b7f8` | `FUN_0079b7f8` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079b922` | `FUN_0079b922` | `src/shared/indinst/indinstparsers.cc` | 6/6 | 100% |
| `0079bc62` | `FUN_0079bc62` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079bd33` | `FUN_0079bd33` | `src/shared/indinst/indinstparsers.cc` | 3/3 | 100% |
| `0079bfc6` | `FUN_0079bfc6` | `src/shared/indinst/indinstparsers.cc` | 2/2 | 100% |
| `0079c30a` | `FUN_0079c30a` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079c628` | `FUN_0079c628` | `src/shared/indinst/indinstparsers.cc` | 2/2 | 100% |
| `0079c993` | `FUN_0079c993` | `src/shared/indinst/indinstparsers.cc` | 1/1 | 100% |
| `0079d78c` | `FUN_0079d78c` | `src/shared/indinst/indinstop.h` | 2/2 | 100% |
| `0079d917` | `FUN_0079d917` | `src/shared/indinst/indinstop.cc` | 1/1 | 100% |
| `0079e220` | `FUN_0079e220` | `src/shared/indinst/indinstop.cc` | 5/5 | 100% |
| `0079e465` | `FUN_0079e465` | `src/shared/indinst/indinstop.cc` | 1/1 | 100% |
| `0079e4bf` | `FUN_0079e4bf` | `src/shared/indinst/indinstop.cc` | 1/1 | 100% |
| `0079e60a` | `FUN_0079e60a` | `src/shared/indinst/indinstop.cc` | 2/2 | 100% |
| `0079fa60` | `FUN_0079fa60` | `src/shared/indinst/indinst.cc` | 3/3 | 100% |
| `0079fc75` | `FUN_0079fc75` | `src/shared/indinst/indinst.cc` | 1/1 | 100% |
| `0079fdcc` | `FUN_0079fdcc` | `src/shared/indinst/indinst.cc` | 4/4 | 100% |
| `007a025b` | `FUN_007a025b` | `src/shared/indinst/indinst.cc` | 4/4 | 100% |
| `007a044d` | `FUN_007a044d` | `src/shared/indinst/indinst.cc` | 2/2 | 100% |
| `007a059c` | `FUN_007a059c` | `src/shared/indinst/indinst.cc` | 6/6 | 100% |
| `007a0b02` | `FUN_007a0b02` | `src/shared/indinst/indinst.cc` | 1/1 | 100% |
| `007a0ed0` | `FUN_007a0ed0` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a0f69` | `FUN_007a0f69` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a1026` | `FUN_007a1026` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a1060` | `FUN_007a1060` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a1098` | `FUN_007a1098` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a11cf` | `FUN_007a11cf` | `src/shared/indoutputgen.cc` | 1/1 | 100% |
| `007a3870` | `FUN_007a3870` | `src/edg/src/attribute.c` | 2/2 | 100% |
| `007a38f6` | `FUN_007a38f6` | `src/edg/src/attribute.c` | 3/3 | 100% |
| `007a3a2b` | `FUN_007a3a2b` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a3bb6` | `FUN_007a3bb6` | `src/edg/src/attribute.c` | 3/3 | 100% |
| `007a3ea1` | `FUN_007a3ea1` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a4089` | `FUN_007a4089` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a433f` | `FUN_007a433f` | `src/edg/src/attribute.c` | 2/2 | 100% |
| `007a4e71` | `FUN_007a4e71` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a5464` | `FUN_007a5464` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a5661` | `FUN_007a5661` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a5cc9` | `FUN_007a5cc9` | `src/edg/src/attribute.c` | 3/3 | 100% |
| `007a669f` | `FUN_007a669f` | `src/edg/src/attribute.c` | 5/5 | 100% |
| `007a703e` | `FUN_007a703e` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a7087` | `FUN_007a7087` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a715b` | `FUN_007a715b` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a7206` | `FUN_007a7206` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a7494` | `FUN_007a7494` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a75be` | `FUN_007a75be` | `src/edg/src/attribute.c` | 1/1 | 100% |
| `007a7dcb` | `FUN_007a7dcb` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007a7e8f` | `FUN_007a7e8f` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007a826f` | `FUN_007a826f` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007a83c5` | `FUN_007a83c5` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007a98a6` | `FUN_007a98a6` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007aa217` | `FUN_007aa217` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007aa3e3` | `FUN_007aa3e3` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007aa5f0` | `FUN_007aa5f0` | `src/edg/src/class_decl.c` | 3/3 | 100% |
| `007ab15f` | `FUN_007ab15f` | `src/edg/src/class_decl.c` | 8/8 | 100% |
| `007ab35b` | `FUN_007ab35b` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007ab685` | `FUN_007ab685` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ab944` | `FUN_007ab944` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007abd13` | `FUN_007abd13` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007abe51` | `FUN_007abe51` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007abffb` | `FUN_007abffb` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ac1fa` | `FUN_007ac1fa` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ac385` | `FUN_007ac385` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ad06b` | `FUN_007ad06b` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ad2de` | `FUN_007ad2de` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ae52e` | `FUN_007ae52e` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007ae6e4` | `FUN_007ae6e4` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007ae9d5` | `FUN_007ae9d5` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007aeb83` | `FUN_007aeb83` | `src/edg/src/class_decl.c` | 2/2 | 100% |
| `007aed13` | `FUN_007aed13` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007aee39` | `FUN_007aee39` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007af08c` | `FUN_007af08c` | `src/edg/src/class_decl.c` | 1/1 | 100% |
| `007af38b` | `FUN_007af38b` | `src/edg/src/class_decl.c` | 1/1 | 100% |
