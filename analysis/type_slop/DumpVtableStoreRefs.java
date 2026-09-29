import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.util.*;

/** Dump only analyzed references that visibly store a recovered table header. */
public class DumpVtableStoreRefs extends GhidraScript {
    private static String clean(String s) {
        return s == null ? "" : s.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: <ghs_vtables.tsv> <out.tsv>");
            return;
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        Set<String> seen = new HashSet<>();
        int rows = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(args[0]));
             PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(args[1])))) {
            out.println("record_va\tclass_name\ttable_header_va\tvptr_va\txref_from\tref_type\tfunction_entry\tfunction_name\tinstruction\tconfidence");
            String line = br.readLine();
            while ((line = br.readLine()) != null) {
                if (line.isBlank()) continue;
                String[] p = line.split("\t", -1);
                if (p.length < 4) continue;
                Address target;
                try {
                    target = currentProgram.getAddressFactory().getAddress(p[2].replace("0x", ""));
                } catch (Exception e) {
                    continue;
                }
                for (Reference ref : getReferencesTo(target)) {
                    Address from = ref.getFromAddress();
                    Instruction ins = currentProgram.getListing().getInstructionContaining(from);
                    if (ins == null) continue;
                    String text = ins.toString();
                    String upper = text.toUpperCase(Locale.ROOT);
                    if (!ins.getMnemonicString().equalsIgnoreCase("MOV") || !upper.contains("PTR [")) continue;
                    Function f = fm.getFunctionContaining(from);
                    if (f == null) continue;
                    String key = p[0] + "|" + from + "|" + f.getEntryPoint();
                    if (!seen.add(key)) continue;
                    out.println(
                        p[0] + "\t" + clean(p[1]) + "\t" + p[2] + "\t" + p[3] + "\t" + from + "\t" +
                        clean(ref.getReferenceType().toString()) + "\t" + f.getEntryPoint() + "\t" + clean(f.getName()) + "\t" +
                        clean(text) + "\t0.98"
                    );
                    rows++;
                }
            }
        }
        println("DumpVtableStoreRefs: rows=" + rows);
    }
}
