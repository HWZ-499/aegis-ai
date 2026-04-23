import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenRedirectJavaSetHeaderFp {
    public void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
        Object next = request.getAttribute("next");
        response.setHeader("Location", String.valueOf(next));
    }
}
