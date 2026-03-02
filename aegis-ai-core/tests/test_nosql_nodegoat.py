"""
测试 NodeGoat 实际代码的 NoSQL 检测
"""
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.analysis.rule_engine import analyze_javascript

# NodeGoat 实际代码模式
nodegoat_code = """
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

if __name__ == "__main__":
    print("=" * 70)
    print("测试 NodeGoat 实际代码的 NoSQL 检测")
    print("=" * 70)
    
    findings = analyze_javascript(nodegoat_code, "user-dao.js", language="javascript")
    
    print(f"\n总检测结果数: {len(findings)}")
    
    nosql_findings = [f for f in findings if f.get("type") == "NOSQL_INJECTION"]
    
    if nosql_findings:
        print(f"\n✅ 检测到 {len(nosql_findings)} 个 NoSQL 注入问题:")
        for finding in nosql_findings:
            print(f"  - 行 {finding.get('line')}: {finding.get('details')}")
    else:
        print("\n❌ 未检测到 NoSQL 注入问题")
        if findings:
            print("   其他检测结果:")
            for finding in findings:
                print(f"     - {finding.get('type')}: {finding.get('details')}")
