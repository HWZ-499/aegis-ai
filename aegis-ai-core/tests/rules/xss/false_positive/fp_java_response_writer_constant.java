import java.io.IOException;
import javax.servlet.http.HttpServletResponse;

public class XssJavaFp {
    public void safe(HttpServletResponse response) throws IOException {
        String message = "Hello, world!";
        response.getWriter().write(message);
    }
}

