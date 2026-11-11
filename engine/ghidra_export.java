// ghidra_export.java — headless-экспорт для LSRE-lite.
// Режимы: overview | decompile <fn|addr> | strings <filter> | xrefs <fn|addr>
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import ghidra.util.task.TaskMonitor;
import java.util.*;

public class ghidra_export extends GhidraScript {
    private static final String BEGIN = "===JSON_BEGIN===";
    private static final String END = "===JSON_END===";

    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') b.append("\\\"");
            else if (c == '\\') b.append("\\\\");
            else if (c == '\n') b.append("\\n");
            else if (c == '\r') { /* пропускаем */ }
            else if (c == '\t') b.append("\\t");
            else if (c < 0x20) b.append(' ');
            else b.append(c);
        }
        return b.toString();
    }

    public void run() throws Exception {
        String[] args = getScriptArgs();
        String mode = args.length > 0 ? args[0] : "overview";
        String arg = args.length > 1 ? args[1] : "";
        StringBuilder sb = new StringBuilder();
        Program program = getCurrentProgram();
        if (program == null) {
            sb.append("{\"error\":\"no program\"}");
        } else {
            sb.append("{\"name\":\"").append(esc(program.getName())).append("\"");
            FunctionManager fm = program.getFunctionManager();

            if (mode.equals("overview") || mode.equals("strings")) {
                if (mode.equals("overview")) {
                    sb.append(",\"functions\":").append(fm.getFunctionCount());
                    List<String> top = new ArrayList<>();
                    FunctionIterator fi = fm.getFunctions(true);
                    int n = 0;
                    while (fi.hasNext() && n < 60) {
                        Function f = fi.next();
                        top.add("\"" + esc(f.getName() + "@" + f.getEntryPoint() + ":" + f.getBody().getNumAddresses()) + "\"");
                        n++;
                    }
                    sb.append(",\"sample\":[").append(String.join(",", top)).append("]");
                }
                sb.append(",\"strings\":[");
                List<String> strings = new ArrayList<>();
                DataIterator di = program.getListing().getDefinedData(true);
                int sc = 0;
                while (di.hasNext() && sc < 400) {
                    Data d = di.next();
                    Object v = d.getValue();
                    if (v instanceof String) {
                        String str = (String) v;
                        if (str.length() >= 3 && (arg.isEmpty() || str.contains(arg))) {
                            if (str.length() > 160) str = str.substring(0, 160);
                            strings.add("\"" + esc(str) + "\"");
                            sc++;
                        }
                    }
                }
                sb.append(String.join(",", strings)).append("]");
                sb.append(",\"external\":[");
                List<String> ext = new ArrayList<>();
                SymbolIterator sit = program.getSymbolTable().getAllSymbols(false);
                int ec = 0;
                while (sit.hasNext() && ec < 200) {
                    Symbol s = sit.next();
                    if (s.isExternal()) { ext.add("\"" + esc(s.getName(true)) + "\""); ec++; }
                }
                sb.append(String.join(",", ext)).append("]");
            } else if (mode.equals("decompile")) {
                Function f = null;
                if (!arg.isEmpty() && (arg.startsWith("0x") || Character.isDigit(arg.charAt(0)))) {
                    Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(arg);
                    f = fm.getFunctionAt(addr);
                } else {
                    for (Function g : fm.getFunctions(true)) {
                        if (g.getName().equals(arg)) { f = g; break; }
                    }
                }
                if (f == null) {
                    sb.append(",\"error\":\"function not found: ").append(esc(arg)).append("\"");
                } else {
                    sb.append(",\"function\":\"").append(esc(f.getName()));
                    sb.append("\",\"address\":\"").append(f.getEntryPoint()).append("\"");
                    DecompInterface ifc = new DecompInterface();
                    ifc.openProgram(program);
                    DecompileResults res = ifc.decompileFunction(f, 120, TaskMonitor.DUMMY);
                    if (res != null && res.decompileCompleted()) {
                        sb.append(",\"code\":\"").append(esc(res.getDecompiledFunction().getC())).append("\"");
                    } else {
                        sb.append(",\"error\":\"decompile failed\"");
                    }
                    ifc.dispose();
                }
            } else if (mode.equals("xrefs")) {
                Function f = null;
                Address addr = null;
                if (!arg.isEmpty() && (arg.startsWith("0x") || Character.isDigit(arg.charAt(0)))) {
                    addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(arg);
                    f = fm.getFunctionAt(addr);
                } else {
                    for (Function g : fm.getFunctions(true)) {
                        if (g.getName().equals(arg)) { f = g; addr = g.getEntryPoint(); break; }
                    }
                }
                sb.append(",\"xrefs\":[");
                List<String> refs = new ArrayList<>();
                if (addr != null) {
                    ReferenceIterator ri = program.getReferenceManager().getReferencesTo(addr);
                    int rc = 0;
                    while (ri.hasNext() && rc < 100) {
                        Reference r = ri.next();
                        Function from = fm.getFunctionContaining(r.getFromAddress());
                        refs.add("\"" + esc((from != null ? from.getName() : "?") + "@" + r.getFromAddress()) + "\"");
                        rc++;
                    }
                }
                sb.append(String.join(",", refs)).append("]");
            }
        }
        sb.append("}");
        println(BEGIN + sb.toString() + END);
    }
}
