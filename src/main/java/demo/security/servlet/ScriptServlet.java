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
        String command = request.getParameter("cmd");
        // Vulnerable: Direct command execution from user input
        Process process = Runtime.getRuntime().exec(command);

        // Vulnerable: Information disclosure in error messages
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            response.getWriter().write("Error executing command: " + e.getMessage());
        }
    }

    protected void executeSystemCommand(HttpServletRequest request) {
        try {
            String[] command = {"/bin/sh", "-c", request.getParameter("command")};
            // Vulnerable: Using ProcessBuilder with user input
            ProcessBuilder builder = new ProcessBuilder(command);
            builder.start();
        } catch (Exception e) {
            // Vulnerable: Swallowing exception
        }
    }
}