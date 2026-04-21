import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionJavaFormatFp {
    public void safe(HttpServletRequest request, Connection connection) throws Exception {
        Statement stmt = connection.createStatement();
        Object tenant = request.getAttribute("tenantId");
        String sql = String.format("SELECT * FROM users WHERE tenant = %s", tenant);
        ResultSet rs = stmt.executeQuery(sql);
    }
}
