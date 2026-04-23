import java.io.ObjectInputStream;
import java.net.ServerSocket;
import java.net.Socket;

public class DeserializationJavaSocketTp {
    public void vulnerable() throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(9876);
             Socket clientSocket = serverSocket.accept();
             ObjectInputStream ois = new ObjectInputStream(clientSocket.getInputStream())) {
            Object obj = ois.readObject();
        }
    }
}
