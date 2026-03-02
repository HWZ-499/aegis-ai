/**
 * TP: findOne() 直接使用 req.body 作为查询条件。
 * 期望检测: NOSQL_INJECTION (Critical)
 */
function login(req, res) {
    db.users.findOne(req.body, (err, user) => {
        if (user) res.json({ success: true });
    });
}
