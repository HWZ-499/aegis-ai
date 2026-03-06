import java.io.File;
import javax.servlet.http.HttpServletRequest;

public class PathTraversalJavaTp {
    public void vulnerable(HttpServletRequest request) {
        String filename = request.getParameter("file");
        File f = new File("/var/www/uploads/" + filename);
    }
}

