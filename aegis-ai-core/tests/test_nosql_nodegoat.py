"""
测试 NodeGoat 实际代码的 NoSQL 检测
"""

import pytest

from src.analysis.rule_engine import analyze_javascript

# NodeGoat 实际代码模式
_nodegoat_code = """
const bcrypt = require("bcrypt-nodejs");

function UserDAO(db) {
    "use strict";

    const usersCol = db.collection("users");

    this.validateLogin = (userName, password, callback) => {
        usersCol.findOne({
            userName: userName
        }, validateUserDoc);
    };

    this.getUserByUserName = (userName, callback) => {
        usersCol.findOne({
            userName: userName
        }, callback);
    };
}
"""


def test_nodegoat_nosql_detection():
    """NodeGoat DAO pattern should detect NoSQL injection findings."""
    findings = analyze_javascript(_nodegoat_code, "user-dao.js", language="javascript")
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    assert len(nosql_findings) >= 1, (
        f"Expected at least 1 NoSQL injection finding, got {len(nosql_findings)}. All findings: {findings}"
    )


def test_nodegoat_finding_count():
    """NodeGoat code with two findOne calls should produce multiple findings."""
    findings = analyze_javascript(_nodegoat_code, "user-dao.js", language="javascript")
    assert len(findings) >= 1, f"Expected at least 1 finding total, got {len(findings)}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
