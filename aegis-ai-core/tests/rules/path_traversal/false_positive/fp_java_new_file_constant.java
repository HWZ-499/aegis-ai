import java.io.File;

public class PathTraversalJavaFp {
    public void safe() {
        String filename = "static.txt";
        File f = new File("/var/www/uploads/" + filename);
    }
}

