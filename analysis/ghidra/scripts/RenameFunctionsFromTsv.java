import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import java.io.*;

public class RenameFunctionsFromTsv extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            println("usage: <labels.tsv>");
            return;
        }
        int renamed = 0;
        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
            String line;
            while ((line = br.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) continue;
                String[] p = line.split("\t", 2);
                if (p.length != 2) continue;
                Function f = currentProgram.getFunctionManager().getFunctionAt(
                    currentProgram.getAddressFactory().getAddress(p[0])
                );
                if (f == null) {
                    println("no function at " + p[0] + " for " + p[1]);
                    continue;
                }
                f.setName(p[1], SourceType.USER_DEFINED);
                renamed++;
            }
        }
        println("RenameFunctionsFromTsv: renamed " + renamed + " functions");
    }
}
