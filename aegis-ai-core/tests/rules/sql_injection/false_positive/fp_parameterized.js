/**
 * FP: 参数化查询 — 安全做法，不应检测为 SQL 注入。
 * 期望: 无 SQL_INJECTION
 */
function getUser(req, db) {
    const name = req.body.name;
    db.query("SELECT * FROM users WHERE name = ?", [name], (err, results) => {
        console.log(results);
    });
}
