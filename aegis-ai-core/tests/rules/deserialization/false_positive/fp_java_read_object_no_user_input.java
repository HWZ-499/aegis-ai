import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;

public class DeserializationJavaFp {
    public void safe() throws IOException, ClassNotFoundException {
        byte[] data = new byte[] {0, 1, 2, 3};
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            Object obj = ois.readObject();
        }
    }
}

