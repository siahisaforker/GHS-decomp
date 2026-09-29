import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;

public class DumpAllStringXrefs extends GhidraScript {
    private String clean(String s) {
        return s.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        File out = new File(args.length > 0 ? args[0] : "all_string_xrefs.tsv");
        PrintWriter pw = new PrintWriter(new BufferedWriter(new FileWriter(out)));
        pw.println("string_addr\tstring\txref_from\tfunction_entry\tfunction_name");
        Listing listing = currentProgram.getListing();
        DataIterator it = listing.getDefinedData(true);
        int strings = 0;
        int refs = 0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d = it.next();
            StringDataInstance sdi = StringDataInstance.getStringDataInstance(d);
            if (sdi == null) continue;
            String s = sdi.getStringValue();
            if (s == null) continue;
            strings++;
            Reference[] rr = getReferencesTo(d.getAddress());
            if (rr.length == 0) {
                pw.println(d.getAddress() + "\t" + clean(s) + "\t\t\t");
            } else {
                for (Reference ref : rr) {
                    refs++;
                    Function f = listing.getFunctionContaining(ref.getFromAddress());
                    pw.println(
                        d.getAddress() + "\t" + clean(s) + "\t" + ref.getFromAddress() + "\t" +
                        (f == null ? "" : f.getEntryPoint()) + "\t" +
                        (f == null ? "" : f.getName())
                    );
                }
            }
        }
        pw.close();
        println("DumpAllStringXrefs: strings=" + strings + " refs=" + refs + " output=" + out.getAbsolutePath());
    }
}
