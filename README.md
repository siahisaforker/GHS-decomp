# GHS-decomp

ai slop decomp of ghs just cause

trying to figure out what the hell green hills 5.3.22 is doing internally so wii u decompilation can maybe suck a little less

current plan is basically:
- bully `ecomppc.exe` in ghidra
- recover whatever function/pass names we can from strings and source path leaks
- use the real compiler as an oracle and throw tiny c/c++ files at it
- learn all the weird ghs codegen habits like register allocation, scheduling, rlwinm spam, etc
- eventually feed all of that into ai and see if it gets noticeably better at matching wii u functions

this is extremely experimental and there is a very real chance this turns into a giant pile of notes and pseudocode

no ghs binaries are going in here. bring your own compiler
