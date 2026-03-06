import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import javax.servlet.http.HttpServletRequest;

public class SqlInjectionJavaFp {
    public void safe(HttpServletRequest request, Connection connection) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement ps = connection.prepareStatement(sql)) {
            ps.setString(1, id);
            try (ResultSet rs = ps.executeQuery()) {
                // 使用参数化查询，避免 SQL 注入
            }
        }
    }
}

