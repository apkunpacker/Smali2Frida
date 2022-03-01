import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.DecimalFormat;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;


public class Smali2Frida {
    
    static final Map<String, String> DT_MAP = Stream.of(new String[][] {
            { "B", "byte" }, 
            { "C", "char" },
            { "D", "double" },
            { "F", "float" }, 
            { "I", "int" },
            { "J", "long" },
            { "S", "short" },
            { "Z", "boolean" },
        }).collect(Collectors.toMap(data -> data[0], data -> data[1]));
        
    static final String[] DT = DT_MAP.keySet().toArray(new String[DT_MAP.size()]);
    
    static final Pattern C_PATTERN = Pattern.compile(".class.+?(\\S+?;)", Pattern.UNICODE_CASE);
    
    static final Pattern M_PATTERN = Pattern.compile(".method.+?(\\S+?)\\((\\S*?)\\)(\\S+)", Pattern.UNICODE_CASE);

    public static void main(String[] args) throws IOException {
        long go = System.nanoTime();
        Path root = Paths.get(args[0]);
        int klas = 0;
        List<Path> paths = smaliFiles(root);
        for (Path path: paths) {
            try {
                if (new String(Files.readAllBytes(path)).contains(".class")) {
                   hook(path, klas);
                   klas++;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        /*
           comment below 3 line if you not need this info
           in final output 
        */
        System.out.println(("Processed classes: " + klas + " / " + paths.size()));
        DecimalFormat format = new DecimalFormat("0.00");
        System.out.println("Duration: " + format.format((System.nanoTime() - go) / 1.0E9d) + " s");
    }

    public static void hook(Path path, int klas) throws IOException {
        String class_name = "";
        Map<Integer, String[]> map = new HashMap<>();
        List<String> allLines = Files.readAllLines(path);
        int i = 0;
        for (String line : allLines) {
            Matcher c = C_PATTERN.matcher(line);
            if (c.matches()) {
                class_name = c.group(1);
                continue;
            }
            if (! class_name.isEmpty()) {
                Matcher m = M_PATTERN.matcher(line);
                if (m.matches()) {
                    String [] starr = {m.group(1), m.group(2)};
                    map.put(i, starr);
                    i++;
                }
            }
        }
        frida(class_name, String.valueOf(klas), map);
    }

    public static void frida(String class_name, String class_num, Map<Integer, String[]> map) {
        class_name = class_name.substring(1, class_name.length() - 1).replaceAll("/",".");
        int last = map.size() - 1;
        StringBuilder snippet = new StringBuilder("Java.perform(function() {\n");
        snippet.append("    var klass").append(class_num).append(" = Java.use(\"").append(class_name).append("\");\n");
        for (Map.Entry<Integer, String[]> entry : map.entrySet()) {
            String[] value = entry.getValue();
            String method_nam = value[0];
            String method_param = value[1];
            String method_name = method_nam;
            if (method_name.equals("<init>")) {
                method_nam = "$init";
            }
            String op = overloadParam(method_param);
            String ap = asperasParam(op);
            int key = entry.getKey();
            snippet.append("\n    klass").append(class_num).append("[\"").append(method_nam).append("\"]").append(".overload(").append(op).append(").implementation = function(").append(ap).append(")\n");
            snippet.append("    {\n");
            snippet.append("        var ret = this[").append("\"").append(method_nam).append("\"]").append("(").append(ap).append(");\n");
            snippet.append("        console.log(\"").append(method_name).append("\", \"called : \", ret);\n");
            snippet.append("        return ret;\n    }");
            if (key == last) {
                snippet.append("    \n})");
            }
        }
        System.out.println(snippet+"\n");
    }

    public static String overloadParam(String method_param) {
        StringBuilder res = new StringBuilder();
        if (method_param.isEmpty()){
            return res.toString();
        }
        for (String el : method_param.split(";")) {
            int i = 0;
            while (i < el.length()) {
                char c = el.charAt(i);
                if (c == 76) {
                   res.append("'").append(el.substring(i + 1).replaceAll("/", ".")).append("', ");
                   break;
                }
                if (c == 91) {
                    if (el.charAt(i+1) == 76) {
                        res.append("'").append(el.substring(i).replaceAll("/", ".")).append("', ");
                        break;
                    }
                    int j = i;
                    while (el.charAt(j) == 91) {
                        j++;
                    }
                    j++;
                    res.append("'").append(el, i, j).append("', ");
                    i = j;
                    continue;
                }
                String s = String.valueOf(c);
                if (Arrays.asList(DT).contains(s)){
                    res.append("'").append(DT_MAP.get(s)).append("', ");
                    i++;
                    continue;
                }
                i++;
            }
        }
        return res.substring(0, res.length()-2);
    }

    public static String asperasParam(String op) {
        StringBuilder res = new StringBuilder();
        if (op.isEmpty()){
            return res.toString();
        }
        for (int i = 0; i < op.split(", ").length; i++) {
            res.append("var").append(i).append(", ");
        }
        return res.substring(0, res.length()-2);
    }

    public static List<Path> smaliFiles(Path path) throws IOException {
        if (!Files.isDirectory(path)) {
            throw new IllegalArgumentException("Not a directory!");
        }
        List<Path> paths;
        try (Stream<Path> walk = Files.walk(path)) {
            paths = walk
                    .filter(Files::isRegularFile)
                    .filter(p -> p.getFileName().toString().endsWith(".smali"))
                    .collect(Collectors.toList());
        }
        return paths;
    }
}
