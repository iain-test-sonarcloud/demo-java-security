package demo.security.servlet;

import demo.security.util.Utils;

import javax.script.ScriptException;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/scripts")
public class ScriptServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String data = request.getParameter("data");
        try {
            Utils.executeJs(data);
        } catch (ScriptException e) {
            throw new RuntimeException(e);
        }
    }

    protected void executeCommand(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        // Removed command injection vulnerability
        response.getWriter().write("Command execution disabled for security reasons");
    }
}