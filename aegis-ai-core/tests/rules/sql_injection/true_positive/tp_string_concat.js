/**
 * TP: SQL 查询拼接用户输入，存在 SQL 注入。
 * 期望检测: SQL_INJECTION (High/Critical)
 */
function getUser(req, db) {
    const name = req.body.name;
    const query = "SELECT * FROM users WHERE name = '" + name + "'";
    db.query(query, (err, results) => {
        console.log(results);
    });
}
