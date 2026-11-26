// ghidra_export.java — LSRE headless export (postScript).
// Аргументы: <mode> [arg]. Modes: overview | decompile | strings | xrefs.
// Выводит JSON между маркерами ===JSON_BEGIN=== / ===JSON_END=== на stdout.
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.demangler.*;
import ghidra.app.decompiler.interface.DecompInterface;
import ghidra.program.util.Reference;

Program cur = currentProgram;
String mode = (args.length >= 1) ? args[0] : "overview";
String arg  = (args.length >= 2) ? args[1] : "";

StringBuilder sb = new StringBuilder();
sb.append("{\"mode\":\"").append(jesc(mode)).append("\",\"program\":\"").append(jesc(cur.getName())).append("\"");

if ("overview".equals(mode)) {
    // functions: count + sample
    long total = 0;
    java.util.List<String> sample = new java.util.ArrayList<>();
    FunctionIterator fit = getFunctionIterator(cur);
    while (fit.hasNext()) {
        Function f = fit.next();
        total++;
        if (sample.size() < 25) sample.add(f.getName() + " @ " + f.getEntryPoint().toString());
    }
    sb.append(",\"functions\":").append(total).append(",\"sample\":[");
    for (int i = 0; i < sample.size(); i++) { if (i > 0) sb.append(','); sb.append('\"').append(jesc(sample.get(i))).append('\"'); }
    sb.append("],");
    // strings: first 80
    java.util.List<String> strs = new java.util.ArrayList<>();
    try {
        java.util.Iterator<StringReference> sit = cur.getString().getStrings();
        while (sit.hasNext() && strs.size() < 80) { StringReference sr = sit.next(); strs.add(getString(sr)); }
    } catch (Throwable t) { sb.append("\"strings_error\":\"").append(jesc(String.valueOf(t))).append("\",\"); }
    sb.append("\"strings\":[");
    for (int i = 0; i < strs.size(); i++) { if (i > 0) sb.append(','); sb.append('\"').append(jesc(strs.get(i))).append('\"'); }
    sb.append("],\");
    // external symbols: first 60
    java.util.List<String> ext = new java.util.ArrayList<>();
    FunctionIterator fit2 = getFunctionIterator(cur);
    while (fit2.hasNext()) { Function f = fit2.next(); if (f.isExternal() && ext.size() < 60) ext.add(f.getName()); }
    sb.append("\"external\":[");
    for (int i = 0; i < ext.size(); i++) { if (i > 0) sb.append(','); sb.append('\"').append(jesc(ext.get(i))).append('\"'); }
    sb.append("]");
} else if ("decompile".equals(mode)) {
    Function f = findFunction(arg);
    if (f == null) {
        sb.append(",\"error\":\"").append(jesc("функция не найдена: ")).append(jesc(arg)).append("\"}");
    } else {
        DecompInterface d = new DecompInterface();
        try {
            d.openProgram(cur);
            d.decompileFunction(f, 0.1f, true, null);
            String code = d.getDecompiledText() == null ? "" : d.getDecompiledText();
            sb.append(",\"function\":\"").append(jesc(f.getName())).append("\",\"address\":\"")
              .append(jesc(f.getEntryPoint().toString())).append("\",\"code\":\"").append(jesc(code)).append("\"");
        } catch (Throwable t) {
            sb.append(",\"error\":\"").append(jesc(String.valueOf(t))).append("\",\"function\":\"").append(jesc(f.getName())).append("\"");
        } finally { try { d.closeProgram(); } catch (Throwable ignore) {} }
        sb.append('}');
    }
} else if ("strings".equals(mode)) {
    java.util.List<String> out = new java.util.ArrayList<>();
    String filter = arg == null ? "" : arg;
    try {
        java.util.Iterator<StringReference> sit = cur.getString().getStrings();
        while (sit.hasNext() && out.size() < 500) {
            StringReference sr = sit.next();
            String txt = getString(sr);
            if (txt == null) continue;
            if (!filter.isEmpty() && !txt.contains(filter)) continue;
            out.add(txt);
        }
    } catch (Throwable t) { out.add("[strings_error] " + t); }
    sb.append(",\"strings\":[");
    for (int i = 0; i < out.size(); i++) { if (i > 0) sb.append(','); sb.append('\"').append(jesc(out.get(i))).append('\"'); }
    sb.append("],\"count\":").append(out.size());
    sb.append('}');
} else if ("xrefs".equals(mode)) {
    Address target = resolveTarget(arg);
    if (target == null) { sb.append(",\"error\":\"").append(jesc("цель не найдена: ")).append(jesc(arg)).append("\"}"); }
    else {
        java.util.List<String> refs = new java.util.ArrayList<>();
        try {
            java.util.Iterator<Reference> rit = cur.getReferenceManager().getReferencesTo(target);
            while (rit.hasNext() && refs.size() < 200) {
                Reference r = rit.next();
                Address src = r.getFromAddress();
                Function sf = getFunctionAt(cur, src);
                String sname = (sf != null ? sf.getName() : src.toString());
                refs.add(sname + " @ " + src.toString() + " [" + r.getReferenceType().toString() + "]");
            }
        } catch (Throwable t) { refs.add("[xrefs_error] " + t); }
        sb.append(",\"target\":\"").append(jesc(target.toString())).append("\",\"xrefs\":[");
        for (int i = 0; i < refs.size(); i++) { if (i > 0) sb.append(','); sb.append('\"').append(jesc(refs.get(i))).append('\"'); }
        sb.append("],\"count\":").append(refs.size());
        sb.append('}');
    }
}
sb.append('}');

System.out.println("===JSON_BEGIN===");
System.out.println(sb.toString());
System.out.println("===JSON_END===");

// ---- helpers ----
function jesc(String s) {
    if (s == null) return "";
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        switch (c) {
            case '"': b.append("\\\""); break;
            case '\\': b.append("\\\\"); break;
            case '\n': b.append("\\n"); break;
            case '\r': b.append(""); break;
            case '\t': b.append("\\t"); break;
            default:
                // Печатный ASCII — как есть; всё остальное экранируем, чтобы JSON всегда был валидным.
                if (c >= 0x20 && c <= 0x7e) { b.append(c); break; }
                // Суррогатная пара — выводим обе части, иначе JSON битый.
                if (c >= 0xd800 && c <= 0xdbff && i + 1 < s.length() && s.charAt(i+1) >= 0xdc00 && s.charAt(i+1) <= 0xdfff) {
                    b.append(String.format("\\u%04x\\u%04x", (int)c, (int)s.charAt(i+1))); i++; break;
                }
                // Одинокий суррогат — заменяем на U+FFFD.
                if (c >= 0xd800 && c <= 0xdfff) { b.append("\\ufffd"); break; }
                b.append(String.format("\\u%04x", (int)c));
        }
    }
    return b.toString();
}
function findFunction(String nameOrAddr) {
    if (nameOrAddr == null || nameOrAddr.isEmpty()) return null;
    String s = nameOrAddr.trim();
    if (s.startsWith("0x") || s.matches("^[0-9a-fA-F]+$")) {
        Address a = cur.getAddressFactory().getAddress(s);
        if (a != null) { Function f = getFunctionAt(cur, a); if (f != null) return f; }
    }
    FunctionIterator it = getFunctionIterator(cur);
    while (it.hasNext()) { Function f = it.next(); if (f.getName().equals(s)) return f; }
    return null;
}
function resolveTarget(String nameOrAddr) {
    Function f = findFunction(nameOrAddr);
    if (f != null) return f.getEntryPoint();
    if (nameOrAddr == null || nameOrAddr.isEmpty()) return null;
    String s = nameOrAddr.trim();
    if (s.startsWith("0x") || s.matches("^[0-9a-fA-F]+$")) { Address a = cur.getAddressFactory().getAddress(s); if (a != null) return a; }
    return null;
}
