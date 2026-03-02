/**
 * FP: 纯字面量查询 — 不含用户输入，不应检测为漏洞。
 * 期望: 无 NOSQL_INJECTION
 */
function getAdmins(db) {
    db.users.find({ role: "admin" }, (err, users) => {
        console.log(users);
    });
}
