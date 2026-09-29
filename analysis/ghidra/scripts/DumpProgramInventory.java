import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.StringDataInstance;
import java.io.*;
import java.util.*;

public class DumpProgramInventory extends GhidraScript {
    private static String clean(String s) {
        return s == null ? "" : s.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: <out_dir>");
            return;
        }
        File outDir = new File(args[0]);
        outDir.mkdirs();

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "program.tsv"))))) {
            pw.println("field\tvalue");
            pw.println("name\t" + clean(currentProgram.getName()));
            pw.println("image_base\t" + currentProgram.getImageBase());
            pw.println("language\t" + clean(currentProgram.getLanguageID().toString()));
            pw.println("compiler_spec\t" + clean(currentProgram.getCompilerSpec().getCompilerSpecID().toString()));
            pw.println("executable_path\t" + clean(currentProgram.getExecutablePath()));
            pw.println("executable_format\t" + clean(currentProgram.getExecutableFormat()));
        }

        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "memory_blocks.tsv"))))) {
            pw.println("name\tstart\tend\tsize\tread\twrite\texecute\tinitialized");
            for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
                pw.println(clean(b.getName()) + "\t" + b.getStart() + "\t" + b.getEnd() + "\t" + b.getSize() +
                    "\t" + b.isRead() + "\t" + b.isWrite() + "\t" + b.isExecute() + "\t" + b.isInitialized());
            }
        }

        FunctionManager fm = currentProgram.getFunctionManager();
        ReferenceManager rm = currentProgram.getReferenceManager();
        int functionCount = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "functions.tsv"))))) {
            pw.println("entry\tbody_min\tbody_max\tbody_size\tname\tsource\tcaller_refs\tcallee_count\tthunk");
            for (Function f : fm.getFunctions(true)) {
                functionCount++;
                int callerRefs = 0;
                ReferenceIterator refs = rm.getReferencesTo(f.getEntryPoint());
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    if (fm.getFunctionContaining(r.getFromAddress()) != null) callerRefs++;
                }
                int calleeCount = f.getCalledFunctions(monitor).size();
                pw.println(f.getEntryPoint() + "\t" + f.getBody().getMinAddress() + "\t" + f.getBody().getMaxAddress() +
                    "\t" + f.getBody().getNumAddresses() + "\t" + clean(f.getName()) + "\t" + f.getSymbol().getSource() +
                    "\t" + callerRefs + "\t" + calleeCount + "\t" + f.isThunk());
            }
        }

        int symbolCount = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "interesting_symbols.tsv"))))) {
            pw.println("address\tname\ttype\tsource\tprimary");
            SymbolIterator it = currentProgram.getSymbolTable().getAllSymbols(true);
            while (it.hasNext()) {
                Symbol s = it.next();
                String n = s.getName();
                String l = n.toLowerCase(Locale.ROOT);
                if (!(l.contains("rtti") || l.contains("vftable") || l.contains("vtable") || l.contains("type_info") || l.contains("class hierarchy") || l.contains("base class"))) continue;
                symbolCount++;
                pw.println(s.getAddress() + "\t" + clean(n) + "\t" + s.getSymbolType() + "\t" + s.getSource() + "\t" + s.isPrimary());
            }
        }

        int rttiStrings = 0;
        try (PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(new File(outDir, "rtti_strings.tsv"))))) {
            pw.println("address\tstring\txref_from\txref_function");
            DataIterator it = currentProgram.getListing().getDefinedData(true);
            while (it.hasNext()) {
                Data d = it.next();
                StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
                if (sdi == null) continue;
                String v = sdi.getStringValue();
                if (v == null || !v.matches("^\\.\\?A[UV].*")) continue;
                rttiStrings++;
                Reference[] refs = getReferencesTo(d.getAddress());
                if (refs.length == 0) pw.println(d.getAddress() + "\t" + clean(v) + "\t\t");
                for (Reference r : refs) {
                    Function f = fm.getFunctionContaining(r.getFromAddress());
                    pw.println(d.getAddress() + "\t" + clean(v) + "\t" + r.getFromAddress() + "\t" + (f == null ? "" : f.getEntryPoint()));
                }
            }
        }

        println("DumpProgramInventory: functions=" + functionCount + " interesting_symbols=" + symbolCount + " rtti_strings=" + rttiStrings);
    }
}
