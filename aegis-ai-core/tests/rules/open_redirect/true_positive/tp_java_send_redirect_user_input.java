import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// TP: 用户可控参数直接传入 sendRedirect，存在开放重定向风险。
public class OpenRedirectJavaTp {
    public void vulnerable(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = request.getParameter("next");
        response.sendRedirect(next);
    }
}

