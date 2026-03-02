/**
 * TP: DAO 文件中 insert 变量参数 — 变量来自 DAO 函数参数（视为外部输入）。
 * 期望检测: NOSQL_INJECTION (High)
 */
function MemosDAO(db) {
    const memosCol = db.collection("memos");

    this.insert = (memo, callback) => {
        const memos = { memo, timestamp: new Date() };
        memosCol.insert(memos, (err, result) => callback(err, result));
    };
}
