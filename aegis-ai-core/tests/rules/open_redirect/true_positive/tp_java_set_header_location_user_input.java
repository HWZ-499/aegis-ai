import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class OpenRedirectJavaSetHeaderTp {
    public void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
        response.setHeader("Location", request.getParameter("next"));
    }
}
