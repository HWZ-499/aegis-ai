/**
 * TP: update() 第二个参数 $set 中的值直接来自 req.body，存在 NoSQL 注入。
 * 期望检测: NOSQL_INJECTION (High)
 */
function updateBenefits(req, db) {
    const startDate = req.body.benefitStartDate;
    db.users.update(
        { _id: req.body.userId },
        { $set: { benefitStartDate: startDate } }
    );
}
