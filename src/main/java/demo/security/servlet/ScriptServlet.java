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

    protected void processXml(HttpServletRequest request, HttpServletResponse response) throws IOException {
        try {
            // Vulnerable: XML parsing without XXE protection
            javax.xml.parsers.DocumentBuilderFactory factory = javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();

            // Vulnerable: Processing XML from user input without validation
            java.io.StringReader reader = new java.io.StringReader(request.getParameter("xml"));
            org.xml.sax.InputSource source = new org.xml.sax.InputSource(reader);
            org.w3c.dom.Document doc = builder.parse(source);

            // Vulnerable: Reflected XSS
            response.getWriter().println("XML processed: " + doc.getDocumentElement().getTextContent());

        } catch (Exception e) {
            // Vulnerable: Information disclosure in error message
            response.getWriter().println("Error processing XML: " + e.toString());
        }
    }

    protected void validateXml(String xml) {
        try {
            // Vulnerable: XSLT processing without security restrictions
            javax.xml.transform.TransformerFactory transformerFactory = javax.xml.transform.TransformerFactory.newInstance();
            javax.xml.transform.Transformer transformer = transformerFactory.newTransformer();

            // Vulnerable: Unrestricted XSLT access
            transformer.transform(
                    new javax.xml.transform.stream.StreamSource(new java.io.StringReader(xml)),
                    new javax.xml.transform.stream.StreamResult(new java.io.StringWriter())
            );
        } catch (Exception e) {
            // Vulnerable: Swallowing exception
        }
    }
}