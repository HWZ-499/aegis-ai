"""快速验证 vulnerable-nodejs-express-mysql 风格代码的规则检出。"""

import pytest

from src.analysis.rule_engine import analyze_javascript

# 模拟 vulnerable-nodejs-express-mysql/service/login.js 全量
_CODE = """
var mysql = require("mysql");
var express = require("express");
var session = require("express-session");
var bodyParser = require("body-parser");
var path = require("path");

var connection = mysql.createConnection({
 host: "db",
 user: "login",
 password: "login",
 database: "login",
});

var app = express();
app.use(session({
 secret: require("crypto").randomBytes(64).toString("hex"),
 resave: true,
 saveUninitialized: true,
}));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.get("/", function (request, response) {
 response.sendFile(path.join(__dirname + "/login.html"));
});

app.post("/auth", function (request, response) {
 var username = request.body.username;
 var password = request.body.password;
 if (username && password) {
 connection.query(
 "SELECT * FROM accounts WHERE username = ? AND password = ?",
 [username, password],
 function (error, results, fields) {
 if (results.length > 0) {
 request.session.loggedin = true;
 request.session.username = username;
 response.redirect("/home");
 } else {
 response.send("Incorrect Username and/or Password!");
 }
 response.end();
 }
 );
 } else {
 response.send("Please enter Username and Password!");
 response.end();
 }
});

app.get("/home", function (request, response) {
 if (request.session.loggedin) {
 response.send("Welcome back, " + request.session.username + "!");
 } else {
 response.send("Please login to view this page!");
 }
 response.end();
});

app.listen(3000);
"""


def test_express_mysql_findings_count():
    """Express+MySQL login code should produce at least one finding."""
    findings = analyze_javascript(_CODE, "login.js")
    assert len(findings) >= 1, "Expected at least one finding from vulnerable express code"


def test_express_mysql_finding_fields():
    """Each finding should have the required 'type' field."""
    findings = analyze_javascript(_CODE, "login.js")
    for f in findings:
        assert "type" in f, f"Finding missing 'type' key: {f}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
