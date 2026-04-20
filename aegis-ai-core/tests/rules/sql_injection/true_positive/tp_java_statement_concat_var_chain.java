import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionJavaVarChainTp {
    public void vulnerable(HttpServletRequest request, Connection connection) throws Exception {
        Statement stmt = connection.createStatement();
        String q = "SELECT * FROM users WHERE id = " + request.getParameter("id");
        ResultSet rs = stmt.executeQuery(q);
    }
}
