package demo.security.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

public class WebUtils {

    public void addCookie(HttpServletResponse response, String name, String value) {
        Cookie c = new Cookie(name, value);
        response.addCookie(c);
    }

    public static void getSessionId(HttpServletRequest request){
        String sessionId = request.getRequestedSessionId();
        if (sessionId != null){
            String ip = "10.40.1.1";
            Socket socket = null;
            try {
                socket = new Socket(ip, 6667);
                socket.getOutputStream().write(sessionId.getBytes(StandardCharsets.UTF_8));
            } catch (IOException e) {
                throw new RuntimeException(e);
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    // TODO - Handle this
                }
            }
        }
    }

    public void setInsecureCookie(HttpServletResponse response, String name, String value) {
        // Vulnerable: Cookie without security attributes
        Cookie cookie = new Cookie(name, value);
        cookie.setMaxAge(36000);
        cookie.setPath("/");
        response.addCookie(cookie);
    }

    public void fetchExternalResource(String url) {
        try {
            // Vulnerable: SSRF - No URL validation
            java.net.URL target = new java.net.URL(url);
            java.net.URLConnection conn = target.openConnection();

            // Vulnerable: No timeout set
            java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(conn.getInputStream())
            );

            String line;
            while ((line = reader.readLine()) != null) {
                // Process the line
                System.out.println(line);
            }
        } catch (Exception e) {
            // Vulnerable: Swallowing exception
        }
    }

    private static final String DEFAULT_PASSWORD = "admin123"; // Vulnerable: Hardcoded credential

    public boolean authenticateUser(String username, String password) {
        // Vulnerable: Constant time comparison not used
        return password.equals(DEFAULT_PASSWORD);
    }
}
