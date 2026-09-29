import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.util.*;

public class DumpLabeledCallGraph extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: <labels.tsv> <out.tsv>");
            return;
        }
        PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(args[1])));
        out.println("focus_addr\tfocus_name\tdirection\tother_addr\tother_name\txref_from");
        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] p = line.split("\t", 2);
                if (p.length != 2) continue;
                Function f = currentProgram.getFunctionManager().getFunctionAt(
                    currentProgram.getAddressFactory().getAddress(p[0])
                );
                if (f == null) continue;

                for (Reference ref : getReferencesTo(f.getEntryPoint())) {
                    Function caller = currentProgram.getFunctionManager().getFunctionContaining(ref.getFromAddress());
                    if (caller != null) {
                        out.println(
                            f.getEntryPoint() + "\t" + f.getName() + "\tcaller\t" +
                            caller.getEntryPoint() + "\t" + caller.getName() + "\t" + ref.getFromAddress()
                        );
                    }
                }
                for (Function callee : f.getCalledFunctions(monitor)) {
                    out.println(
                        f.getEntryPoint() + "\t" + f.getName() + "\tcallee\t" +
                        callee.getEntryPoint() + "\t" + callee.getName() + "\t"
                    );
                }
            }
        }
        out.close();
    }
}
