import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.Function;
import java.io.*;

public class DecompileAddresses extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("usage: <labels.tsv> <out_dir>");
            return;
        }
        File outDir = new File(args[1]);
        outDir.mkdirs();
        DecompInterface di = new DecompInterface();
        di.openProgram(currentProgram);
        int count = 0;
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
                DecompileResults dr = di.decompileFunction(f, 120, monitor);
                if (!dr.decompileCompleted()) continue;
                File out = new File(outDir, p[0] + "_" + p[1] + ".c");
                try (PrintWriter pw = new PrintWriter(out)) {
                    pw.println("/* " + p[1] + " @ " + p[0] + " */");
                    pw.println(dr.getDecompiledFunction().getC());
                }
                count++;
            }
        }
        di.dispose();
        println("DecompileAddresses: wrote " + count + " functions");
    }
}
