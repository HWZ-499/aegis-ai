import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import javax.servlet.http.HttpServletRequest;

class DownloadController {
    void copyUpload(HttpServletRequest request) throws Exception {
        String name = request.getParameter("file");
        File f = new File("/srv/uploads", name);
        Files.copy(Path.of("/srv/source.txt"), Path.of("/srv/uploads", name));
        Files.move(Path.of("/srv/source.txt"), Path.of("/srv/archive", name));
    }
}
