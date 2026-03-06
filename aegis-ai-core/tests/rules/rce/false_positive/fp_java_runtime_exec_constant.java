import java.io.IOException;

public class RceJavaFp {
    public void safe() throws IOException {
        // 固定命令，不包含用户输入，规则应视为低风险示例
        Runtime.getRuntime().exec("ls -la");
    }
}

