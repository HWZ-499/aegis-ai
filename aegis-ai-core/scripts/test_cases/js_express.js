/**
 * JS/Express 合成测试用例
 * TP（漏洞）/ TN（安全）/ PROP（传播污点）
 * 覆盖：内联箭头函数、具名函数中间件、解构参数、赋值式箭头函数、Sanitizer
 */

const express = require('express');
const app = express();
const db = require('./db');

// ── TP-1: 内联箭头函数 → SQL 注入 ────────────────────────────
// EXPECT: sql_injection, line 13
app.get('/user', (req, res) => {
    const id = req.query.id;
    db.query("SELECT * FROM users WHERE id = " + id);
});

// ── TP-2: 内联箭头函数 → RCE（eval）────────────────────────
// EXPECT: rce, line 20
app.post('/eval', (req, res) => {
    const code = req.body.code;
    eval(code);
});

// ── TP-3: 具名函数中间件 → XSS ──────────────────────────────
// EXPECT: xss, line 27
function renderName(req, res) {
    const name = req.query.name;
    res.send('<h1>Hello ' + name + '</h1>');
}
app.get('/hello', renderName);

// ── TP-4: 赋值式箭头函数 → SQL 注入 ─────────────────────────
// EXPECT: sql_injection, line 35
const searchHandler = (req, res) => {
    const keyword = req.query.q;
    db.query("SELECT * FROM items WHERE name LIKE '%" + keyword + "%'");
};
app.get('/search', searchHandler);

// ── TP-5: 解构参数 req.body → SQL 注入 ──────────────────────
// EXPECT: sql_injection, line 43
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    db.query("SELECT * FROM users WHERE user='" + username + "' AND pass='" + password + "'");
});

// ── TP-6: 解构赋值传播 { username } = req.body ───────────────
// EXPECT: sql_injection, line 51
app.post('/register', (req, res) => {
    const { username, email } = req.body;
    db.query("INSERT INTO users (user, email) VALUES ('" + username + "', '" + email + "')");
});

// ── TP-7: 模板字符串注入 ────────────────────────────────────
// EXPECT: sql_injection, line 58
app.get('/profile', (req, res) => {
    const uid = req.params.id;
    db.query(`SELECT * FROM users WHERE id = ${uid}`);
});

// ── TP-8: 多跳变量传播 ──────────────────────────────────────
// EXPECT: sql_injection, line 65
app.get('/item', (req, res) => {
    const raw = req.query.sku;
    const sku = raw.trim();
    db.query("SELECT * FROM items WHERE sku = '" + sku + "'");
});

// ── TP-9: 函数表达式赋值 → RCE ──────────────────────────────
// EXPECT: rce, line 73
const execHandler = function(req, res) {
    const cmd = req.query.cmd;
    require('child_process').exec(cmd);
};
app.get('/exec', execHandler);

// ── TP-10: req.params 路径参数注入 ──────────────────────────
// EXPECT: sql_injection, line 80
app.delete('/user/:id', (req, res) => {
    const userId = req.params.id;
    db.query("DELETE FROM users WHERE id = " + userId);
});

// ── TN-1: parseInt 净化（安全）──────────────────────────────
// EXPECT: no finding
app.get('/page', (req, res) => {
    const page = parseInt(req.query.page, 10);
    db.query("SELECT * FROM posts LIMIT 10 OFFSET " + page);
});

// ── TN-2: 参数化查询（安全）────────────────────────────────
// EXPECT: no finding
app.get('/safe-user', (req, res) => {
    const id = req.query.id;
    db.query("SELECT * FROM users WHERE id = ?", [id]);
});

// ── TN-3: 校验函数返回值不传播污点 ──────────────────────────
// EXPECT: no finding
const isValidInput = (req, res) => {
    return req.body.value !== null;
};
app.post('/validate', (req, res) => {
    const isValid = isValidInput(req, res);
    res.json({ valid: isValid });
});

// ── TN-4: htmlspecialchars 等价处理（安全）───────────────────
// EXPECT: no finding
app.get('/comment', (req, res) => {
    const comment = req.query.comment;
    const safe = comment.replace(/[<>"'&]/g, c => `&#${c.charCodeAt(0)};`);
    res.send(safe);
});

// ── PROP-1: req.body 解构重命名传播 ─────────────────────────
// EXPECT: sql_injection, line 117
app.post('/update', (req, res) => {
    const { username: user, password: pass } = req.body;
    db.query("UPDATE users SET password='" + pass + "' WHERE user='" + user + "'");
});

// ── PROP-2: 具名函数 + 内部变量传播 ─────────────────────────
// EXPECT: sql_injection, line 124
function buildQuery(req, res) {
    const term = req.query.term;
    const escaped = term + ' ';
    db.query("SELECT * FROM products WHERE name = '" + escaped + "'");
}
app.get('/products', buildQuery);

// ── PROP-3: 箭头函数赋值 + req.headers 传播 ─────────────────
// EXPECT: sql_injection, line 132
const headerHandler = (req, res) => {
    const apiKey = req.headers['x-api-key'];
    const logEntry = "INSERT INTO logs (key) VALUES ('" + apiKey + "')";
    db.query(logEntry);
};
app.use('/api', headerHandler);
