#!/usr/bin/env python3
from pathlib import Path
from collections import defaultdict, Counter
import re

inp=Path('analysis/ghidra/out/compiler_string_xrefs.tsv')
out=Path('analysis/prime/source_file_function_map.tsv')
summary=Path('analysis/prime/source_module_summary.md')
rows=inp.read_text(errors='replace').splitlines()
by_file=defaultdict(lambda: defaultdict(int))
by_func=defaultdict(lambda: defaultdict(int))

def canon(s):
    s=s.lstrip('@').replace('\\','/')
    s=re.sub(r'^\.\./','',s)
    return s

for line in rows[1:]:
    p=line.split('\t')
    if len(p)<5: continue
    s, faddr, fname = p[1], p[3], p[4]
    if not faddr: continue
    if 'src\\' not in s and 'src/' not in s: continue
    s=canon(s)
    if not s.startswith('src/'): continue
    by_file[s][(faddr,fname)] += 1
    by_func[(faddr,fname)][s] += 1

with out.open('w') as f:
    f.write('source_file\tfunction_entry\tfunction_name\txrefs\tconfidence\n')
    for src in sorted(by_file):
        for (addr,name),cnt in sorted(by_file[src].items(), key=lambda kv:(-kv[1],kv[0][0])):
            total=sum(by_func[(addr,name)].values())
            conf=cnt/total if total else 0
            f.write(f'{src}\t{addr}\t{name}\t{cnt}\t{conf:.3f}\n')

# Roll up by subtree and source file.
subtree=Counter()
for src, funcs in by_file.items():
    parts=src.split('/')
    key='/'.join(parts[:3]) if len(parts)>=3 else src
    subtree[key]+=len(funcs)

with summary.open('w') as f:
    f.write('# Embedded-source → function map\n\n')
    f.write(f'Parsed **{sum(len(v) for v in by_file.values())} source-file/function associations** across **{len(by_file)} embedded source paths** and **{len(by_func)} functions**. Associations come from direct references to embedded source-path strings; they are strong module breadcrumbs, not proof of exact original function names.\n\n')
    f.write('## Largest source-file clusters\n\n')
    f.write('| source file | funcs | xrefs | address span |\n|---|---:|---:|---|\n')
    ranked=sorted(by_file.items(), key=lambda kv:(-len(kv[1]), kv[0]))
    for src, funcs in ranked[:40]:
        addrs=sorted(int(a,16) for a,_ in funcs)
        xrefs=sum(funcs.values())
        f.write(f'| `{src}` | {len(funcs)} | {xrefs} | `0x{addrs[0]:08x}–0x{addrs[-1]:08x}` |\n')
    f.write('\n## Subtree totals\n\n')
    f.write('| subtree | unique function associations |\n|---|---:|\n')
    for k,v in subtree.most_common():
        f.write(f'| `{k}` | {v} |\n')
    f.write('\n## High-confidence single-file assignments\n\n')
    chosen=[]
    for (addr,name), files in by_func.items():
        total=sum(files.values())
        src,cnt=max(files.items(), key=lambda kv:kv[1])
        conf=cnt/total
        if conf>=0.80 and cnt>=1:
            chosen.append((int(addr,16),addr,name,src,cnt,total,conf))
    f.write(f'{len(chosen)} functions have ≥80% of their embedded-source xrefs pointing at one source file.\n\n')
    f.write('| address | current name | likely source | refs | confidence |\n|---|---|---|---:|---:|\n')
    for _,addr,name,src,cnt,total,conf in sorted(chosen)[:120]:
        f.write(f'| `{addr}` | `{name}` | `{src}` | {cnt}/{total} | {conf:.0%} |\n')

print(summary)
print(out)
print('source paths',len(by_file),'functions',len(by_func),'associations',sum(len(v) for v in by_file.values()))
