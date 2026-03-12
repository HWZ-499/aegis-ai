"""
测试 NoSQL 注入规则
"""

import pytest

from src.analysis.rule_engine import analyze_javascript

# 测试用例1: db.users.findOne({ user: req.body.user })
_test_code1 = """
const express = require('express');
const router = express.Router();

router.post('/login', (req, res) => {
    db.users.findOne({ user: req.body.user }, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
"""

# 测试用例2: User.find({ email: req.query.email })
_test_code2 = """
const User = require('./models/User');

app.get('/users', (req, res) => {
    User.find({ email: req.query.email }, (err, users) => {
        if (err) return res.status(500).send(err);
        res.json(users);
    });
});
"""

# 测试用例3: db.users.findOne({ user: req.body.user, password: req.body.password })
_test_code3 = """
router.post('/session', (req, res) => {
    db.users.findOne({ user: req.body.user, password: req.body.password }, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
"""

# 测试用例4: usersCol.findOne({ userName: userName }) - 函数参数模式（NodeGoat实际模式）
_test_code4 = """
function UserDAO(db) {
    const usersCol = db.collection("users");

    this.getUserByUserName = (userName, callback) => {
        usersCol.findOne({
            userName: userName
        }, callback);
    };
}
"""


def test_nosql_findone_req_body():
    """db.users.findOne({ user: req.body.user }) should detect NoSQL injection."""
    findings = analyze_javascript(_test_code1, "test.js", language="javascript")
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    assert len(nosql_findings) >= 1, f"Expected NoSQL injection finding, got {findings}"


def test_nosql_find_req_query():
    """User.find({ email: req.query.email }) should detect NoSQL injection."""
    findings = analyze_javascript(_test_code2, "test.js", language="javascript")
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    assert len(nosql_findings) >= 1, f"Expected NoSQL injection finding, got {findings}"


def test_nosql_findone_multiple_req_body():
    """db.users.findOne with multiple req.body fields should detect NoSQL injection."""
    findings = analyze_javascript(_test_code3, "test.js", language="javascript")
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    assert len(nosql_findings) >= 1, f"Expected NoSQL injection finding, got {findings}"


def test_nosql_findone_function_param():
    """usersCol.findOne({ userName: userName }) DAO pattern should detect NoSQL injection."""
    findings = analyze_javascript(_test_code4, "test.js", language="javascript")
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    assert len(nosql_findings) >= 1, f"Expected NoSQL injection finding, got {findings}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
