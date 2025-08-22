package demo.security.servlet;

import demo.security.util.Utils;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@WebServlet("/files")
public class FileServlet extends HttpServlet {
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        String data = request.getParameter("data");
        Utils.deleteFile(data);
    }

    protected void readFile(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String fileName = request.getParameter("file");
        // Vulnerable: Path traversal
        java.io.File file = new java.io.File(fileName);

        // Vulnerable: Information disclosure
        if (file.exists()) {
            java.io.FileInputStream fis = new java.io.FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            response.getOutputStream().write(data);
            fis.close();
        }
    }

    private static final String UPLOAD_DIR = "/tmp/uploads/";

    protected void saveFile(HttpServletRequest request) {
        try {
            String fileName = request.getParameter("filename");
            String content = request.getParameter("content");

            // Vulnerable: Predictable file location and no input validation
            java.io.FileWriter writer = new java.io.FileWriter(UPLOAD_DIR + fileName);
            writer.write(content);
            writer.close();

            // Vulnerable: Insecure file permissions
            java.io.File file = new java.io.File(UPLOAD_DIR + fileName);
            file.setReadable(true, false);
            file.setWritable(true, false);
        } catch (Exception e) {
            // Vulnerable: Swallowing exception
        }
    }
}
