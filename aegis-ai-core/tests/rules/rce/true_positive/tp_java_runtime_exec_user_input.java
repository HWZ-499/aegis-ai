import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class RceJavaTp {
    public void vulnerable(HttpServletRequest request) throws IOException {
        String cmd = request.getParameter("cmd");
        Runtime.getRuntime().exec(cmd);
    }
}

