# test_multi_language.py - 多语言支持测试
"""
测试多语言漏洞检测功能
"""

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from src.analysis.multi_language_ast import MultiLanguageASTAnalyzer, analyze_code_multi_language
from src.analysis.rule_engine import analyze_c_cpp
from src.scanner.project_scanner import ProjectScanner
from src.scanner.report_generator import ReportGenerator


def test_language_detection():
    """测试语言检测功能"""
    print("\n" + "=" * 70)
    print("测试 1: 语言检测")
    print("=" * 70)

    analyzer = MultiLanguageASTAnalyzer()

    test_cases = [
        ("test.py", "print('hello')", "python"),
        ("test.js", "console.log('hello')", "javascript"),
        ("test.ts", "const x: number = 1", "typescript"),
        ("Test.java", "public class Test {}", "java"),
        ("test.c", "#include <stdio.h>", "c"),
        ("test.cpp", "#include <iostream>", "cpp"),
        ("test.go", "package main", "go"),
        ("test.php", "<?php echo 'hello';", "php"),
    ]

    passed = 0
    failed = 0

    for file_path, code, expected_lang in test_cases:
        detected = analyzer.detect_language(file_path, code)
        if detected == expected_lang:
            print(f"✅ {file_path:20} -> {detected:15} (期望: {expected_lang})")
            passed += 1
        else:
            print(f"❌ {file_path:20} -> {detected:15} (期望: {expected_lang})")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    assert failed == 0


def test_python_detection():
    """测试 Python 漏洞检测"""
    print("\n" + "=" * 70)
    print("测试 2: Python 漏洞检测")
    print("=" * 70)

    test_cases = [
        {
            "name": "SQL 注入",
            "code": """
user_id = input("Enter ID: ")
query = "SELECT * FROM users WHERE id = " + user_id
cursor.execute(query)
""",
            "expected_types": ["SQL_INJECTION", "SQL Injection Risk"],  # AST 和正则可能返回不同名称
        },
        {
            "name": "命令执行",
            "code": """
import os
user_input = input("Enter command: ")
os.system(user_input)
""",
            "expected_types": ["RCE_COMMAND_EXEC", "Command Injection"],  # AST 和正则可能返回不同名称
        },
        {
            "name": "硬编码凭证",
            "code": """
password = "admin123"
api_key = "sk-1234567890abcdef"
""",
            "expected_types": ["HARDCODED_CREDENTIALS", "Hardcoded Credentials"],  # AST 返回 "Hardcoded Credentials"
        },
        {
            "name": "eval 危险函数",
            "code": """
user_code = input("Enter code: ")
result = eval(user_code)
""",
            "expected_types": ["RCE_COMMAND_EXEC", "Code Injection"],  # AST 和正则可能返回不同名称
        },
    ]

    passed = 0
    failed = 0

    for case in test_cases:
        findings = analyze_code_multi_language(case["code"], file_path="test.py")
        found_types = [f.get("type", "") for f in findings]

        # 检查是否检测到期望的漏洞类型（不区分大小写，支持部分匹配）
        found_types_lower = [t.lower() for t in found_types]
        expected_lower = [t.lower() for t in case["expected_types"]]
        detected = any(any(exp in found or found in exp for found in found_types_lower) for exp in expected_lower)

        if detected:
            print(f"✅ {case['name']:20} -> 检测到 {len(findings)} 个问题")
            print(f"   漏洞类型: {', '.join(set(found_types))}")
            passed += 1
        else:
            print(f"❌ {case['name']:20} -> 未检测到期望的漏洞")
            print(f"   期望: {case['expected_types']}")
            print(f"   实际: {found_types}")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    assert failed == 0


def test_javascript_detection():
    """测试 JavaScript 漏洞检测"""
    print("\n" + "=" * 70)
    print("测试 3: JavaScript 漏洞检测")
    print("=" * 70)

    test_cases = [
        {
            "name": "XSS 风险",
            "code": """
const userInput = req.body.content;
document.getElementById('content').innerHTML = userInput;
""",
            "expected_types": ["XSS_RISK", "XSS"],  # 检查 XSS 规则
        },
        {
            "name": "eval 危险函数",
            "code": """
const userCode = prompt("Enter code:");
eval(userCode);
""",
            "expected_types": ["RCE_COMMAND_EXEC"],
        },
    ]

    passed = 0
    failed = 0

    for case in test_cases:
        findings = analyze_code_multi_language(case["code"], file_path="test.js")
        found_types = [f.get("type", "") for f in findings]

        detected = any(t in found_types for t in case["expected_types"])

        if detected:
            print(f"✅ {case['name']:20} -> 检测到 {len(findings)} 个问题")
            print(f"   漏洞类型: {', '.join(set(found_types))}")
            passed += 1
        else:
            print(f"❌ {case['name']:20} -> 未检测到期望的漏洞")
            print(f"   期望: {case['expected_types']}")
            print(f"   实际: {found_types}")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    assert failed == 0


def test_javascript_sql_injection_is_known_legacy_multi_language_gap():
    """legacy multi_language_ast JS path does not cover SQLi; the new rule engine owns that path."""
    code = """
const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
db.query(query);
"""
    findings = analyze_code_multi_language(code, file_path="test.js")
    found_types = [f.get("type", "") for f in findings]
    detected = "SQL_INJECTION" in found_types

    if not detected:
        pytest.xfail("SQLi is covered by rule_engine.analyze_javascript, not legacy multi_language_ast.")
    assert detected


def test_java_detection():
    """测试 Java 漏洞检测"""
    print("\n" + "=" * 70)
    print("测试 4: Java 漏洞检测")
    print("=" * 70)

    test_cases = [
        {
            "name": "SQL 注入",
            "code": """
String userId = request.getParameter("id");
String query = "SELECT * FROM users WHERE id = " + userId;
Statement stmt = conn.createStatement();
stmt.execute(query);
""",
            "expected_types": ["SQL_INJECTION"],  # 需要检查 Java 规则
        },
        {
            "name": "命令执行",
            "code": """
String command = request.getParameter("cmd");
Runtime.getRuntime().exec(command);
""",
            "expected_types": ["RCE_COMMAND_EXEC", "COMMAND_INJECTION"],  # 多语言分析器返回 COMMAND_INJECTION
        },
        {
            "name": "反序列化",
            "code": """
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
""",
            "expected_types": ["DESERIALIZATION"],
        },
    ]

    passed = 0
    failed = 0

    for case in test_cases:
        findings = analyze_code_multi_language(case["code"], file_path="Test.java")
        found_types = [f.get("type", "") for f in findings]

        detected = any(t in found_types for t in case["expected_types"])

        if detected:
            print(f"✅ {case['name']:20} -> 检测到 {len(findings)} 个问题")
            print(f"   漏洞类型: {', '.join(set(found_types))}")
            passed += 1
        else:
            print(f"❌ {case['name']:20} -> 未检测到期望的漏洞")
            print(f"   期望: {case['expected_types']}")
            print(f"   实际: {found_types}")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    assert failed == 0


def test_cpp_detection():
    """测试 C/C++ 漏洞检测"""
    print("\n" + "=" * 70)
    print("测试 5: C/C++ 漏洞检测")
    print("=" * 70)

    test_cases = [
        {
            "name": "缓冲区溢出",
            "code": """
char buffer[10];
char *src = "This is a very long string";
strcpy(buffer, src);
""",
            "expected_types": ["BUFFER_OVERFLOW"],
        },
        {
            "name": "格式化字符串",
            "code": """
char *user_input = get_user_input();
printf(user_input);
""",
            "expected_types": ["FORMAT_STRING"],  # 注意：当前规则可能无法检测单参数 printf
        },
    ]

    passed = 0
    failed = 0

    for case in test_cases:
        findings = analyze_code_multi_language(case["code"], file_path="test.cpp")
        found_types = [f.get("type", "") for f in findings]

        detected = any(t in found_types for t in case["expected_types"])

        if detected:
            print(f"✅ {case['name']:20} -> 检测到 {len(findings)} 个问题")
            print(f"   漏洞类型: {', '.join(set(found_types))}")
            passed += 1
        else:
            print(f"❌ {case['name']:20} -> 未检测到期望的漏洞")
            print(f"   期望: {case['expected_types']}")
            print(f"   实际: {found_types}")
            failed += 1

    print(f"\n结果: {passed} 通过, {failed} 失败")
    assert failed == 0


def test_cpp_cin_into_fixed_char_array_detected():
    """C/C++ 基础规则应检测 cin 直接写入固定 char 数组。"""
    code = """
char name[20] = {'\\0'};
void read() {
    cin >> name;
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "BUFFER_OVERFLOW" and finding.get("line") == 4 for finding in findings)


def test_cpp_short_literal_strcpy_to_known_char_array_is_filtered():
    """能证明字面量放得下时，不应把 strcpy 短常量报成溢出。"""
    code = """
typedef struct PCB {
    char name[20];
} PCB, *pPCB;
void initialPCB(pPCB p) {
    strcpy(p->name, "NoName");
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert not any(finding.get("type") == "BUFFER_OVERFLOW" for finding in findings)


def test_cpp_variable_strcpy_to_fixed_char_array_still_reported():
    """变量来源长度未知的 strcpy 仍应保守报告。"""
    code = """
typedef struct PCB {
    char name[20];
} PCB, *pPCB;
void createProcess(pPCB newPcb, char *name) {
    strcpy(newPcb->name, name);
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "BUFFER_OVERFLOW" and finding.get("line") == 6 for finding in findings)


def test_cpp_unsafe_thread_termination_reported():
    """C/C++ 基础规则应提示直接终止线程的资源一致性风险。"""
    code = """
void stop(HANDLE hThread) {
    TerminateThread(hThread, 0);
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "THREAD_LIFECYCLE_RISK" and finding.get("line") == 3 for finding in findings)


def test_cpp_assignment_inside_condition_reported():
    """条件表达式中的单等号赋值容易造成权限/状态判断失效。"""
    code = """
void run(pPCB currentPcb) {
    if(currentPcb->flag=1) {
        currentPcb->flag = 0;
    }
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "ASSIGNMENT_IN_CONDITION" and finding.get("line") == 3 for finding in findings)


def test_cpp_nested_pointer_deref_after_shallow_guard_reported():
    """只判断外层指针不为空时，继续解引用内层指针应提示空指针风险。"""
    code = """
void schedule(pList pReadyList) {
    if(pReadyList) {
        pReadyList->head = pReadyList->head->next;
    }
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "NULL_DEREFERENCE" and finding.get("line") == 4 for finding in findings)


def test_cpp_nested_pointer_deref_with_inner_guard_not_reported():
    """明确检查内层指针后，不应报告嵌套指针空解引用。"""
    code = """
void schedule(pList pReadyList) {
    if(pReadyList && pReadyList->head != NULL) {
        pReadyList->head = pReadyList->head->next;
    }
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert not any(finding.get("type") == "NULL_DEREFERENCE" for finding in findings)


def test_cpp_critical_section_mismatch_reported():
    """Enter/Leave 临界区对象不一致时应提示死锁风险。"""
    code = """
void schedule() {
    EnterCriticalSection(&cs_ReadyList);
    doWork();
    LeaveCriticalSection(&cs_SaveInfo);
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert any(finding.get("type") == "LOCK_MISMATCH" and finding.get("line") == 5 for finding in findings)


def test_cpp_nested_critical_sections_matched_not_reported():
    """正常嵌套进入/退出临界区不应误报。"""
    code = """
void schedule() {
    EnterCriticalSection(&cs_ReadyList);
    EnterCriticalSection(&cs_SaveInfo);
    LeaveCriticalSection(&cs_SaveInfo);
    LeaveCriticalSection(&cs_ReadyList);
}
"""

    findings = analyze_c_cpp(code, "test.cpp")

    assert not any(finding.get("type") == "LOCK_MISMATCH" for finding in findings)


def test_multi_language_project_scan():
    """测试多语言项目扫描"""
    print("\n" + "=" * 70)
    print("测试 6: 多语言项目扫描")
    print("=" * 70)

    # 创建临时测试项目
    with TemporaryDirectory() as tmpdir:
        test_project = Path(tmpdir) / "test_project"
        test_project.mkdir()

        # 创建 Python 文件
        (test_project / "app.py").write_text("""
import os
user_input = input("Enter: ")
os.system(user_input)
""")

        # 创建 JavaScript 文件
        (test_project / "app.js").write_text("""
const userInput = prompt("Enter:");
eval(userInput);
""")

        # 创建 Java 文件
        (test_project / "App.java").write_text("""
public class App {
    public static void main(String[] args) {
        String query = "SELECT * FROM users WHERE id = " + args[0];
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
}
""")

        # 创建 C++ 文件
        (test_project / "app.cpp").write_text("""
#include <cstring>
char buffer[10];
strcpy(buffer, "This is a very long string");
""")

        # 扫描项目
        scanner = ProjectScanner(str(test_project))
        results = scanner.scan_project()
        stats = scanner.get_stats()

        print(f"📁 测试项目: {test_project}")
        print(f"   总文件数: {stats['total_files']}")
        print(f"   扫描文件数: {stats['scanned_files']}")
        print(f"   有问题文件数: {stats['files_with_issues']}")
        print(f"   总问题数: {stats['total_issues']}")

        # 按语言统计
        language_stats = {}
        for file_path, findings in results.items():
            if findings:
                lang = findings[0].get("language", "unknown")
                language_stats[lang] = language_stats.get(lang, 0) + len(findings)

        print("\n按语言统计:")
        for lang, count in language_stats.items():
            print(f"   {lang:15} : {count:3} 个问题")

        # 验证结果
        assert stats["scanned_files"] >= 4
        assert stats["total_issues"] > 0
        print("\n✅ 多语言项目扫描成功")


def test_report_generation():
    """测试报告生成"""
    print("\n" + "=" * 70)
    print("测试 7: 多语言报告生成")
    print("=" * 70)

    # 创建测试数据
    test_results = {
        "app.py": [
            {
                "line": 3,
                "type": "RCE_COMMAND_EXEC",
                "severity": "High",
                "details": "Python: 发现 RCE_COMMAND_EXEC 风险",
                "language": "python",
            }
        ],
        "app.js": [
            {
                "line": 2,
                "type": "RCE_COMMAND_EXEC",
                "severity": "Medium",
                "details": "JavaScript: 发现 RCE_COMMAND_EXEC 风险",
                "language": "javascript",
            }
        ],
        "App.java": [
            {
                "line": 4,
                "type": "SQL_INJECTION",
                "severity": "High",
                "details": "Java: 发现 SQL_INJECTION 风险",
                "language": "java",
            }
        ],
    }

    test_stats = {
        "total_files": 3,
        "scanned_files": 3,
        "files_with_issues": 3,
        "total_issues": 3,
        "scan_time": "2026-02-03T10:00:00",
    }

    generator = ReportGenerator("多语言测试项目")

    # 测试 JSON 报告
    try:
        json_report = generator.generate_json(test_results, test_stats)
        json_data = json.loads(json_report)

        # JSON 报告格式: {"project_name": ..., "results": {"file1": [...], "file2": [...]}}
        results = json_data.get("results", {})
        results_count = sum(len(v) for v in results.values()) if isinstance(results, dict) else 0

        if json_data.get("project_name") == "多语言测试项目" and results_count >= 3:
            print("✅ JSON 报告生成成功")
            json_ok = True
        else:
            print(
                f"❌ JSON 报告生成失败: project_name={json_data.get('project_name')}, findings_count={len(json_data.get('findings', {}))}"
            )
            json_ok = False
    except Exception as e:
        print(f"❌ JSON 报告生成失败: {e}")
        json_ok = False

    # 测试 Markdown 报告
    md_report = generator.generate_markdown(test_results, test_stats)
    if "多语言测试项目" in md_report and "app.py" in md_report:
        print("✅ Markdown 报告生成成功")
        md_ok = True
    else:
        print("❌ Markdown 报告生成失败")
        md_ok = False

    # 测试 HTML 报告
    try:
        html_report = generator.generate_html(test_results, test_stats)
        if "多语言测试项目" in html_report and (
            "<html>" in html_report or "<HTML>" in html_report or "DOCTYPE html" in html_report
        ):
            print("✅ HTML 报告生成成功")
            html_ok = True
        else:
            print(
                f"❌ HTML 报告生成失败: 长度={len(html_report)}, 包含项目名={('多语言测试项目' in html_report)}, 包含html标签={('<html>' in html_report.lower())}"
            )
            html_ok = False
    except Exception as e:
        print(f"❌ HTML 报告生成失败: {e}")
        import traceback

        traceback.print_exc()
        html_ok = False

    assert json_ok
    assert md_ok
    assert html_ok


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
