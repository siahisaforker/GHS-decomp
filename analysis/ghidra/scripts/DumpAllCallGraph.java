import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import java.io.*;

public class DumpAllCallGraph extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: <out.tsv>");
            return;
        }
        FunctionManager fm = currentProgram.getFunctionManager();
        int functions = 0;
        long edges = 0;
        try (PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(args[0])))) {
            out.println("caller_addr\tcaller_name\tcallee_addr\tcallee_name");
            for (Function caller : fm.getFunctions(true)) {
                functions++;
                for (Function callee : caller.getCalledFunctions(monitor)) {
                    out.println(caller.getEntryPoint() + "\t" + caller.getName() + "\t" +
                        callee.getEntryPoint() + "\t" + callee.getName());
                    edges++;
                }
            }
        }
        println("DumpAllCallGraph: functions=" + functions + " edges=" + edges);
    }
}
