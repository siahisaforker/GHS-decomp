import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;
import java.io.*;
import java.util.*;

public class MapCompilerStrings extends GhidraScript {
    private static final String[] KEYS = {
        "dooptimize", "propagateconstants", "LivenessDf", "PostLivenessDf",
        "LOOPUNROLL", "OPTLOOPS", "find_loop_invariants", "possible_induction_var",
        "SIMD_vectorize", "check_possible_alias", "ObjectMotion", "flatten_code",
        "Purgedupjumps", "tablify_cases", "Cse Sort", "Final Allc",
        "resource_scheduler", "coalesce", "spill", "allocregs", "liveness",
        "peephole", "optbranches", "treepeep", "SUBSTITUT", "TAILCALL",
        "DFLOW", "RLWIMI", "PREDICT BRANCH", "SHARE BRANCHES",
        "src\\compilers", "src/compilers", "src\\edg", "src/edg",
        "src\\shared", "src/shared", "src\\asm", "src/asm"
    };
    private boolean interesting(String s) {
        String l=s.toLowerCase(Locale.ROOT);
        for (String k: KEYS) if (l.contains(k.toLowerCase(Locale.ROOT))) return true;
        return false;
    }
    private String clean(String s) { return s.replace("\t"," ").replace("\r"," ").replace("\n"," "); }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        File out = new File(args.length>0 ? args[0] : "compiler_string_xrefs.tsv");
        PrintWriter pw=new PrintWriter(new BufferedWriter(new FileWriter(out)));
        pw.println("string_addr\tstring\txref_from\tfunction_entry\tfunction_name");
        Listing listing=currentProgram.getListing();
        DataIterator it=listing.getDefinedData(true);
        int hits=0, refs=0;
        while (it.hasNext() && !monitor.isCancelled()) {
            Data d=it.next();
            StringDataInstance sdi=StringDataInstance.getStringDataInstance(d);
            if (sdi==null) continue;
            String s=sdi.getStringValue();
            if (s==null || !interesting(s)) continue;
            hits++;
            Reference[] rr=getReferencesTo(d.getAddress());
            if (rr.length==0) pw.println(d.getAddress()+"\t"+clean(s)+"\t\t\t");
            for (Reference ref: rr) {
                refs++;
                Address from=ref.getFromAddress();
                Function f=listing.getFunctionContaining(from);
                pw.println(d.getAddress()+"\t"+clean(s)+"\t"+from+"\t"+(f==null?"":f.getEntryPoint())+"\t"+(f==null?"":f.getName()));
            }
        }
        pw.close();
        println("MapCompilerStrings: interesting_strings="+hits+" refs="+refs+" output="+out.getAbsolutePath());
    }
}
