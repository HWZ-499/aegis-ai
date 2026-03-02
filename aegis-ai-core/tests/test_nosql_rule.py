"""
测试 NoSQL 注入规则
"""
import sys
from pathlib import Path

# 添加项目根目录到路径
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.analysis.rule_engine import analyze_javascript

# 测试用例1: db.users.findOne({ user: req.body.user })
test_code1 = """
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
test_code2 = """
const User = require('./models/User');

app.get('/users', (req, res) => {
    User.find({ email: req.query.email }, (err, users) => {
        if (err) return res.status(500).send(err);
        res.json(users);
    });
});
"""

# 测试用例3: db.users.findOne({ user: req.body.user, password: req.body.password })
test_code3 = """
router.post('/session', (req, res) => {
    db.users.findOne({ user: req.body.user, password: req.body.password }, (err, user) => {
        if (err) return res.status(500).send(err);
        res.json(user);
    });
});
"""

# 测试用例4: usersCol.findOne({ userName: userName }) - 函数参数模式（NodeGoat实际模式）
test_code4 = """
function UserDAO(db) {
    const usersCol = db.collection("users");
    
    this.getUserByUserName = (userName, callback) => {
        usersCol.findOne({
            userName: userName
        }, callback);
    };
}
"""

if __name__ == "__main__":
    print("=" * 70)
    print("测试 NoSQL 注入规则")
    print("=" * 70)
    
    test_cases = [
        ("测试用例1: db.users.findOne({ user: req.body.user })", test_code1),
        ("测试用例2: User.find({ email: req.query.email })", test_code2),
        ("测试用例3: db.users.findOne({ user: req.body.user, password: req.body.password })", test_code3),
        ("测试用例4: usersCol.findOne({ userName: userName }) - 函数参数模式", test_code4),
    ]
    
    for name, code in test_cases:
        print(f"\n{name}")
        print("-" * 70)
        findings = analyze_javascript(code, "test.js", language="javascript")
        
        nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
        
        if nosql_findings:
            print(f"✅ 检测到 {len(nosql_findings)} 个 NoSQL 注入问题:")
            for finding in nosql_findings:
                print(f"  - 行 {finding.get('line')}: {finding.get('details')}")
        else:
            print("❌ 未检测到 NoSQL 注入问题")
            print(f"   总检测结果数: {len(findings)}")
            if findings:
                print("   其他检测结果:")
                for finding in findings:
                    print(f"     - {finding.get('type')}: {finding.get('details')}")
