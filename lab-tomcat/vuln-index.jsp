<%@ page import="java.io.*,java.util.Base64" %>
<%
// Lab-only deserialization sink. Pass ?data=<base64> or POST a Cookie header
// named "session" containing base64-encoded serialized Java object data.
// Real exploit requires a gadget chain (commons-collections etc.) on the
// classpath — left out so the lab demonstrates the pattern, not the impact.
String data = request.getParameter("data");
if (data == null) {
    javax.servlet.http.Cookie[] cookies = request.getCookies();
    if (cookies != null) {
        for (javax.servlet.http.Cookie c : cookies) {
            if ("session".equals(c.getName())) {
                data = c.getValue();
                break;
            }
        }
    }
}

if (data == null || data.isEmpty()) {
    out.println("<html><body><h1>vuln-app</h1>");
    out.println("<p>Send ?data=&lt;base64-serialized-object&gt; or set a 'session' cookie.</p>");
    out.println("</body></html>");
    return;
}

try {
    byte[] raw = Base64.getDecoder().decode(data);
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(raw));
    Object o = ois.readObject();
    out.println("deserialized: " + o);
} catch (Exception e) {
    out.println("error: " + e.getMessage());
}
%>
