import javax.servlet.http.HttpServletRequest;

public class LocalExecMethodFp {
    public void exec(String jobId) {
        // Business workflow method, not Runtime.exec().
    }

    public void handle(HttpServletRequest request) {
        exec(request.getParameter("jobId"));
    }
}
