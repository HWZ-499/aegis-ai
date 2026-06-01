import javax.script.ScriptEngine;
import javax.script.ScriptException;
import javax.servlet.http.HttpServletRequest;

public class ScriptEngineEvalTp {
    public void vulnerable(HttpServletRequest request, ScriptEngine engine) throws ScriptException {
        engine.eval(request.getParameter("code"));
    }
}
