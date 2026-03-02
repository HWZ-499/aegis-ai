/**
 * TP: eval() 执行来自 req.body 的用户输入，存在 RCE 漏洞。
 * 期望检测: RCE_COMMAND_EXEC (Critical)
 */
function calculate(req, res) {
    const expression = req.body.expr;
    const result = eval(expression);
    res.json({ result });
}
