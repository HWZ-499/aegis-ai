import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

// FP: sendRedirect 仅使用常量路径，不包含用户输入。
public class OpenRedirectJavaFp {
    public void safe(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String next = "/home";
        response.sendRedirect(next);
    }
}

