/**
 * FP: 使用 textContent 输出用户输入 — textContent 会自动转义，不存在 XSS。
 * 期望: 无 XSS_RISK
 */
function showMessage(req) {
    const userInput = req.query.message;
    document.getElementById("output").textContent = userInput;
}
