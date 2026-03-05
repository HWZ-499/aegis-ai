# rule_based_audit.py - 纯规则审计引擎（不依赖 AI）
"""
.. deprecated:: 1.2.0
    此模块为旧版审计桥接层，依赖 ``ast_analyzer`` 和 ``security_rules``。
    新代码请使用 ``rule_engine.py``。计划在 v1.5 中移除。

纯规则审计引擎：结合 AST 分析和正则规则，不依赖外部 AI API。
即使 AI 不可用，也能给出基础的安全审计报告。
"""
import logging
from typing import List, Dict, Any
from src.analysis.ast_analyzer import analyze_code_ast
from src.analysis.security_rules import scan_code_locally

logger = logging.getLogger("aegis")

def merge_findings(ast_findings: List[Dict], regex_findings: List[Dict]) -> List[Dict]:
    """
    合并 AST 和正则规则的检测结果，去重并统一格式。

    去重策略：
    - 同文件同行同类型视为重复，优先保留 AST 版本（精度更高）
    - 若 severity 不同，保留更严重的一方
    - PATH_TRAVERSAL：AST 版本严格优先于 regex 版本，防止旧 regex 规则
      与新 AST 规则双重报告同一漏洞

    Args:
        ast_findings:   AST 分析结果（新规则引擎产出）
        regex_findings: 正则规则扫描结果（旧规则层产出）

    Returns:
        合并后的检测结果列表，按行号排序。
    """
    # key: (file, line, type) → finding 字典
    findings_dict: Dict[tuple, Dict[str, Any]] = {}

    # 严重程度优先级（数字越大越严重）
    _SEVERITY_ORDER = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}

    def _sev_pri(severity: str) -> int:
        return _SEVERITY_ORDER.get(severity, 0)

    def _make_key(finding: Dict, file_override: str = "") -> tuple:
        """构造 (file, line, type) 去重键。"""
        file_ = file_override or finding.get("file", finding.get("file_path", ""))
        return (file_, finding.get("line", 0), finding.get("type", ""))

    # ── 第一遍：处理 AST 结果（优先级高）──────────────────────────
    for finding in ast_findings:
        key = _make_key(finding)
        severity = finding.get("severity", "Medium")
        findings_dict[key] = {
            "line":     finding.get("line", 0),
            "type":     finding.get("type", "Unknown"),
            "severity": severity,
            "details":  finding.get("details", ""),
            "source":   "AST",
            # 保留完整字段（file、taint_var 等）供报告层使用
            **{k: v for k, v in finding.items()
               if k not in ("line", "type", "severity", "details")},
        }

    # ── 第二遍：处理 Regex 结果 ──────────────────────────────────
    for finding in regex_findings:
        key = _make_key(finding)
        severity = finding.get("severity")
        if not severity:
            confidence = finding.get("confidence", "Low/Medium")
            severity = (
                "High" if "High" in confidence
                else "Medium" if "Medium" in confidence
                else "Low"
            )

        if key not in findings_dict:
            findings_dict[key] = {
                "line":     finding.get("line", 0),
                "type":     finding.get("type", "Unknown"),
                "severity": severity,
                "details":  finding.get("content", finding.get("details", "")),
                "source":   "Regex",
                **{k: v for k, v in finding.items()
                   if k not in ("line", "type", "severity", "details", "content")},
            }
        else:
            existing = findings_dict[key]
            existing_source = existing.get("source", "")

            # PATH_TRAVERSAL：AST 版严格优先，regex 版不覆盖
            if finding.get("type") == "PATH_TRAVERSAL" and "AST" in existing_source:
                existing["source"] = "AST+Regex"
                continue

            # 其他类型：若 severity 更严重则更新
            if _sev_pri(severity) > _sev_pri(existing.get("severity", "Medium")):
                existing["severity"] = severity
            # 标记为双重检测
            existing["source"] = "AST+Regex"

    merged = list(findings_dict.values())
    merged.sort(key=lambda x: x.get("line", 0))
    return merged


def generate_rule_based_report(findings: List[Dict], code_text: str, filename: str = "unknown") -> str:
    """
    基于规则检测结果生成审计报告（不依赖 AI）。
    
    Args:
        findings: 合并后的检测结果
        code_text: 源代码内容
        filename: 文件名
        
    Returns:
        Markdown 格式的审计报告
    """
    if not findings:
        return f"""# 代码安全审计报告

**文件**: `{filename}`

## ✅ 检测结果

未发现明显的安全漏洞。

**说明**: 
- AST 静态分析：未发现高危函数调用
- 正则规则扫描：未发现已知漏洞模式

**建议**: 
虽然未发现明显漏洞，但建议：
1. 进行人工代码审查
2. 进行动态测试（如渗透测试）
3. 关注业务逻辑漏洞（规则引擎无法检测）
"""

    # 按严重程度分组
    critical = [f for f in findings if f.get('severity') == 'Critical']
    high = [f for f in findings if f.get('severity') == 'High']
    medium = [f for f in findings if f.get('severity') == 'Medium']
    low = [f for f in findings if f.get('severity') == 'Low']

    report = f"""# 代码安全审计报告

**文件**: `{filename}`  
**检测方法**: AST 静态分析 + 正则规则扫描  
**检测时间**: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

## 📊 检测摘要

| 严重程度 | 数量 |
|---------|------|
| 🔴 Critical（严重） | {len(critical)} |
| 🟠 High（高） | {len(high)} |
| 🟡 Medium（中） | {len(medium)} |
| 🟢 Low（低） | {len(low)} |
| **总计** | **{len(findings)}** |

---

## 🔍 详细发现

"""

    # 按严重程度输出
    severity_order = ['Critical', 'High', 'Medium', 'Low']
    severity_emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}
    
    for severity in severity_order:
        findings_by_severity = [f for f in findings if f.get('severity') == severity]
        if not findings_by_severity:
            continue
        
        report += f"\n### {severity_emoji[severity]} {severity} 级别漏洞 ({len(findings_by_severity)} 个)\n\n"
        
        for i, finding in enumerate(findings_by_severity, 1):
            report += f"#### {i}. {finding['type']} (第 {finding['line']} 行)\n\n"
            report += f"**检测方法**: {finding.get('source', 'Unknown')}\n\n"
            report += f"**详情**: {finding['details']}\n\n"
            
            # 显示相关代码行
            lines = code_text.split('\n')
            line_num = finding['line']
            if 0 < line_num <= len(lines):
                code_line = lines[line_num - 1].strip()
                if code_line:
                    report += f"**代码**:\n```python\n{code_line}\n```\n\n"
            
            report += "---\n\n"

    # 修复建议
    report += """## 💡 修复建议

### 通用建议

1. **代码注入/命令注入**
   - 避免使用 `eval()`, `exec()`, `os.system()` 等危险函数
   - 使用参数化查询（SQL）或安全的 API（命令执行）

2. **SQL 注入**
   - 使用参数化查询（Prepared Statements）
   - 避免字符串拼接 SQL 语句

3. **XSS 风险**
   - 对所有用户输入进行 HTML 转义
   - 使用安全的模板引擎（自动转义）

4. **硬编码凭证**
   - 使用环境变量或密钥管理服务
   - 不要在代码中直接写密码、密钥

5. **路径遍历**
   - 验证文件路径，限制访问范围
   - 使用白名单机制

6. **反序列化风险**
   - 避免反序列化不可信数据
   - 使用安全的序列化格式（如 JSON）

---

## ⚠️ 注意事项

本报告基于**静态分析**（AST + 正则规则），存在以下限制：

1. **无法检测逻辑漏洞**：如越权访问、业务逻辑错误
2. **无法检测运行时问题**：如竞态条件、内存泄漏
3. **可能存在误报**：需要人工验证
4. **无法检测动态行为**：如网络请求、文件 I/O 的实际行为

**建议**: 结合动态测试、人工审查、渗透测试等方法，进行全面安全评估。

---

*报告生成时间: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*
"""

    return report


def audit_code_with_rules_only(code_text: str, filename: str = "unknown") -> Dict[str, Any]:
    """
    纯规则审计（不依赖 AI）。
    
    Args:
        code_text: 源代码内容
        filename: 文件名
        
    Returns:
        包含检测结果和报告的字典
    """
    logger.info("开始纯规则审计", extra={"filename": filename})
    
    # 1. AST 分析
    ast_findings = analyze_code_ast(code_text)
    logger.info("AST 分析完成", extra={"findings_count": len(ast_findings)})
    
    # 2. 正则规则扫描（传递文件名用于语言检测）
    regex_findings = scan_code_locally(code_text, file_path=filename)
    logger.info("正则规则扫描完成", extra={"findings_count": len(regex_findings)})
    
    # 3. 合并结果
    merged_findings = merge_findings(ast_findings, regex_findings)
    logger.info("结果合并完成", extra={"total_findings": len(merged_findings)})
    
    # 4. 生成报告
    report = generate_rule_based_report(merged_findings, code_text, filename)
    
    return {
        "findings": merged_findings,
        "report": report,
        "ast_count": len(ast_findings),
        "regex_count": len(regex_findings),
        "total_count": len(merged_findings)
    }
