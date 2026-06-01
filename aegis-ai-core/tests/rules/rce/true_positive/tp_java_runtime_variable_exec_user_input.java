import java.io.IOException;
import javax.servlet.http.HttpServletRequest;

public class RuntimeVariableExecTp {
    public void vulnerable(HttpServletRequest request) throws IOException {
        Runtime runtime = Runtime.getRuntime();
        runtime.exec(request.getParameter("cmd"));
    }
}
