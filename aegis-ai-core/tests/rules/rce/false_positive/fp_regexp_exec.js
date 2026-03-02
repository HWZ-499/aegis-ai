/**
 * FP: 正则表达式的 exec()，不是命令执行。
 * 期望: 无 RCE_COMMAND_EXEC
 */
function validateEmail(email) {
    const pattern = /^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$/;
    return pattern.exec(email) !== null;
}
