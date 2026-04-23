import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionJavaFormatTp {
    public void vulnerable(HttpServletRequest request, Connection connection) throws Exception {
        Statement stmt = connection.createStatement();
        String sql = String.format("SELECT * FROM users WHERE id = %s", request.getParameter("id"));
        ResultSet rs = stmt.executeQuery(sql);
    }
}
