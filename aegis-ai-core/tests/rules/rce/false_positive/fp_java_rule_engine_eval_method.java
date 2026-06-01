import javax.servlet.http.HttpServletRequest;

class RuleEngine {
    public void eval(String ruleName) {
        // Evaluates a whitelisted business rule name, not script code.
    }
}

public class RuleEngineEvalMethodFp {
    public void handle(HttpServletRequest request, RuleEngine rules) {
        rules.eval(request.getParameter("rule"));
    }
}
