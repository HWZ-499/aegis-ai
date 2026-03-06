import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.util.Base64;
import javax.servlet.http.HttpServletRequest;

public class DeserializationJavaTp {
    public void vulnerable(HttpServletRequest request) throws IOException, ClassNotFoundException {
        String payload = request.getParameter("payload");
        byte[] data = Base64.getDecoder().decode(payload);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
        }
    }
}

