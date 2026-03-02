/**
 * TP: 将用户输入赋值给 innerHTML，存在 XSS 漏洞。
 * 期望检测: XSS_RISK (High)
 */
function showMessage(req) {
    const userInput = req.query.message;
    document.getElementById("output").innerHTML = userInput;
}
