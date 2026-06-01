import javax.servlet.http.HttpServletRequest;

class JobRunner {
    public void start(String jobId) {
        // Starts an application job, not a ProcessBuilder.
    }
}

public class ApplicationStartMethodFp {
    public void handle(HttpServletRequest request, JobRunner jobRunner) {
        jobRunner.start(request.getParameter("jobId"));
    }
}
