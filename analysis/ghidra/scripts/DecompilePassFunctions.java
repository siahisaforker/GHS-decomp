import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.*;

public class DecompilePassFunctions extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length<2){ println("usage: <xref_tsv> <out_dir>"); return; }
        File tsv=new File(args[0]), outdir=new File(args[1]); outdir.mkdirs();
        Set<String> addrs=new LinkedHashSet<>();
        try(BufferedReader br=new BufferedReader(new FileReader(tsv))){
            String l; br.readLine();
            while((l=br.readLine())!=null){ String[] p=l.split("\\t",-1); if(p.length>=4 && !p[3].isEmpty()){ String st=p.length>1?p[1].toLowerCase():""; if(!st.contains("src\\\\") && !st.contains("src/")) addrs.add(p[3]); } }
        }
        DecompInterface di=new DecompInterface(); di.openProgram(currentProgram);
        Listing listing=currentProgram.getListing(); int n=0;
        for(String a:addrs){
            if(monitor.isCancelled()) break;
            Function f=listing.getFunctionAt(currentProgram.getAddressFactory().getAddress(a)); if(f==null) continue;
            DecompileResults dr=di.decompileFunction(f,60,monitor); if(!dr.decompileCompleted()) continue;
            String safe=(a+"_"+f.getName()).replaceAll("[^A-Za-z0-9_.-]","_");
            try(PrintWriter pw=new PrintWriter(new File(outdir,safe+".c"))){
                pw.println("/* "+f.getName()+" @ "+a+" */"); pw.println(dr.getDecompiledFunction().getC());
            }
            n++;
        }
        di.dispose(); println("DecompilePassFunctions: wrote "+n+" functions to "+outdir);
    }
}
