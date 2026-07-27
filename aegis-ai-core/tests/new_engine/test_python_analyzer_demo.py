"""
test_python_analyzer_demo.py

目的：
- 演示新规则架构（AnalysisContext + SecurityRule + PythonAnalyzer）是否工作正常；
- 使用两条规则：
  - PythonSQLInjectionAstRule（AST 版 SQLi）
  - PythonRCEAstRule（AST 版 RCE 检测）

使用方法（在 aegis-ai-core 目录）：
    python -m tests.new_engine.test_python_analyzer_demo
"""

from __future__ import annotations

from pathlib import Path

from src.analysis.analyzers.python_analyzer import PythonAnalyzer
from src.analysis.rules import PythonRCEAstRule, PythonSQLInjectionAstRule


def main() -> None:
    """
    运行一个简单示例，打印扫描结果。
    """
    sample_code = """
import os
import subprocess

def dangerous_eval(user_input):
    eval(user_input)

def dangerous_system(cmd):
    os.system(cmd)

def dangerous_sql(user_input, conn):
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    conn.execute(query)
"""

    rules = [
        PythonRCEAstRule(),
        PythonSQLInjectionAstRule(),
    ]
    analyzer = PythonAnalyzer(rules)

    findings = analyzer.analyze(sample_code, file_path=Path("demo.py"))

    print("=== 新规则引擎示例输出 ===")
    for f in findings:
        print(f"[{f.get('severity')}] {f.get('type')} (line {f.get('line')}): {f.get('details')}")


if __name__ == "__main__":
    main()
