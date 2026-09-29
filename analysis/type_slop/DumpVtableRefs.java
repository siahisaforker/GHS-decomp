import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import java.io.*;

/** Export Ghidra references to recovered GHS custom-vtable addresses.
 *
 * The table header is the value constructors actually install.  The first
 * slot-pair address is exported too because some code refers to the callable
 * pair array directly.  normalize_vptr_refs.py later keeps only table-header
 * references whose source instruction is a memory-writing MOV.
 */
public class DumpVtableRefs extends GhidraScript {
    private static String clean(String s) {
        return s == null ? "" : s.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    private void emitRefs(PrintWriter out, FunctionManager fm, String recordVa,
                          String className, String kind, String targetText) {
        Address target = currentProgram.getAddressFactory().getAddress(targetText.replace("0x", ""));
        if (target == null) return;
        for (Reference ref : getReferencesTo(target)) {
            Address from = ref.getFromAddress();
            Function f = fm.getFunctionContaining(from);
            Instruction ins = currentProgram.getListing().getInstructionAt(from);
            out.println(
                recordVa + "\t" + clean(className) + "\t" + kind + "\t" + target + "\t" + from + "\t" +
                (f == null ? "" : f.getEntryPoint()) + "\t" + (f == null ? "" : clean(f.getName())) + "\t" +
                clean(ref.getReferenceType().toString()) + "\t" + (ins == null ? "" : clean(ins.toString()))
            );
        }
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: <ghs_vtables.tsv> <out.tsv>");
            return;
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        int before = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(args[0]));
             PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(args[1])))) {
            out.println("class_record_va\tclass_name\ttarget_kind\ttarget_va\txref_from\tfunction_entry\tfunction_name\tref_type\tinstruction");
            String line = br.readLine(); // header
            while ((line = br.readLine()) != null) {
                String[] p = line.split("\t", -1);
                if (p.length < 5) continue;
                emitRefs(out, fm, p[0], p[1], "table_header", p[2]);
                emitRefs(out, fm, p[0], p[1], "slot_pairs", p[3]);
                before++;
            }
        }
        println("DumpVtableRefs: scanned_vtables=" + before);
    }
}
