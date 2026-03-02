"""快速验证 vulnerable-nodejs-express-mysql 风格代码的规则检出。"""
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.analysis.rule_engine import analyze_javascript

# 模拟 vulnerable-nodejs-express-mysql/service/login.js 全量
CODE = """
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

if __name__ == "__main__":
    findings = analyze_javascript(CODE, "login.js")
    print("Findings count:", len(findings))
    for f in findings:
        print(" ", f.get("type"), "L" + str(f.get("line", "")), (f.get("details") or "")[:70])
