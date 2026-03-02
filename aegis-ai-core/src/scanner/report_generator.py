# report_generator.py - 报告生成器
"""
生成多种格式的安全扫描报告：JSON、HTML、SARIF、Markdown
"""
import html
import json
from typing import Any, Dict, List
from datetime import datetime
from pathlib import Path


def _esc(value: Any) -> str:
    """
    对动态内容进行 HTML 转义，防止 XSS。

    所有用户可控数据（finding 的 details / content / type 等）
    在注入 HTML 模板前 **必须** 经过此函数。
    """
    return html.escape(str(value)) if value is not None else ""


class ReportGenerator:
    """
    报告生成器
    
    支持多种格式的报告导出
    """
    
    def __init__(self, project_name: str = "Unknown Project"):
        """
        初始化报告生成器
        
        Args:
            project_name: 项目名称
        """
        self.project_name = project_name
        self.scan_time = datetime.now().isoformat()
    
    def generate_json(self, results: Dict[str, List[Dict]], stats: Dict) -> str:
        """
        生成 JSON 格式报告
        
        Args:
            results: 扫描结果字典
            stats: 统计信息
            
        Returns:
            JSON 格式的报告字符串
        """
        report = {
            "project_name": self.project_name,
            "scan_time": self.scan_time,
            "summary": {
                "total_files": stats.get('total_files', 0),
                "scanned_files": stats.get('scanned_files', 0),
                "files_with_issues": stats.get('files_with_issues', 0),
                "total_issues": stats.get('total_issues', 0),
                "scan_time_seconds": stats.get('scan_time', 0)
            },
            "severity_stats": stats.get('severity_stats', {}),
            "results": results
        }
        
        return json.dumps(report, indent=2, ensure_ascii=False)
    
    def generate_markdown(self, results: Dict[str, List[Dict]], stats: Dict) -> str:
        """
        生成 Markdown 格式报告
        
        Args:
            results: 扫描结果字典
            stats: 统计信息
            
        Returns:
            Markdown 格式的报告字符串
        """
        lines = []
        
        # 标题
        lines.append(f"# 🔒 安全扫描报告 - {self.project_name}")
        lines.append("")
        lines.append(f"**扫描时间**: {self.scan_time}")
        lines.append("")
        
        # 摘要
        lines.append("## 📊 扫描摘要")
        lines.append("")
        lines.append("| 指标 | 数量 |")
        lines.append("|------|------|")
        lines.append(f"| 总文件数 | {stats.get('total_files', 0)} |")
        lines.append(f"| 扫描文件数 | {stats.get('scanned_files', 0)} |")
        lines.append(f"| 有问题文件数 | {stats.get('files_with_issues', 0)} |")
        lines.append(f"| 总问题数 | {stats.get('total_issues', 0)} |")
        scan_time = stats.get('scan_time', 0)
        if isinstance(scan_time, (int, float)):
            lines.append(f"| 扫描耗时 | {scan_time:.2f} 秒 |")
        else:
            lines.append(f"| 扫描耗时 | {scan_time} |")
        lines.append("")
        
        # 严重程度统计
        severity_stats = stats.get('severity_stats', {})
        if severity_stats:
            lines.append("## 🎯 严重程度统计")
            lines.append("")
            lines.append("| 严重程度 | 数量 |")
            lines.append("|---------|------|")
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_stats.get(severity, 0)
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                lines.append(f"| {emoji} {severity} | {count} |")
            lines.append("")
        
        # 详细结果
        if results:
            lines.append("## 🔍 详细发现")
            lines.append("")
            
            for file_path, findings in results.items():
                lines.append(f"### 📄 {file_path}")
                lines.append("")
                lines.append(f"**问题数量**: {len(findings)}")
                lines.append("")
                
                # 按严重程度分组
                by_severity = {}
                for finding in findings:
                    severity = finding.get('severity', 'Medium')
                    if severity not in by_severity:
                        by_severity[severity] = []
                    by_severity[severity].append(finding)
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    if severity not in by_severity:
                        continue
                    
                    emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                    lines.append(f"#### {emoji} {severity} 级别")
                    lines.append("")
                    
                    for finding in by_severity[severity]:
                        lines.append(f"**第 {finding.get('line', '?')} 行** - {finding.get('type', 'Unknown')}")
                        lines.append("")
                        lines.append(f"> {finding.get('details', 'No details')}")
                        lines.append("")
                        if finding.get('content'):
                            lines.append(f"```python")
                            lines.append(finding['content'])
                            lines.append("```")
                            lines.append("")
        
        return "\n".join(lines)
    
    def generate_html(self, results: Dict[str, List[Dict]], stats: Dict) -> str:
        """
        生成 HTML 格式报告
        
        Args:
            results: 扫描结果字典
            stats: 统计信息
            
        Returns:
            HTML 格式的报告字符串
        """
        # 处理扫描时间显示
        scan_time = stats.get('scan_time', 0)
        if isinstance(scan_time, (int, float)):
            scan_time_display = f"{scan_time:.2f} 秒"
        else:
            scan_time_display = str(scan_time)
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告 - {_esc(self.project_name)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #1976d2; }}
        .file-section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }}
        .finding {{
            margin: 10px 0;
            padding: 10px;
            background-color: #fff;
            border-left: 3px solid #ccc;
        }}
        .finding.critical {{ border-left-color: #d32f2f; }}
        .finding.high {{ border-left-color: #f57c00; }}
        .finding.medium {{ border-left-color: #fbc02d; }}
        .finding.low {{ border-left-color: #1976d2; }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 安全扫描报告 - {_esc(self.project_name)}</h1>
        <p><strong>扫描时间</strong>: {_esc(self.scan_time)}</p>
        
        <h2>📊 扫描摘要</h2>
        <table>
            <tr>
                <th>指标</th>
                <th>数量</th>
            </tr>
            <tr>
                <td>总文件数</td>
                <td>{_esc(stats.get('total_files', 0))}</td>
            </tr>
            <tr>
                <td>扫描文件数</td>
                <td>{_esc(stats.get('scanned_files', 0))}</td>
            </tr>
            <tr>
                <td>有问题文件数</td>
                <td>{_esc(stats.get('files_with_issues', 0))}</td>
            </tr>
            <tr>
                <td>总问题数</td>
                <td>{_esc(stats.get('total_issues', 0))}</td>
            </tr>
            <tr>
                <td>扫描耗时</td>
                <td>{_esc(scan_time_display)}</td>
            </tr>
        </table>
"""
        
        # 严重程度统计
        severity_stats = stats.get('severity_stats', {})
        if severity_stats:
            html += """
        <h2>🎯 严重程度统计</h2>
        <table>
            <tr>
                <th>严重程度</th>
                <th>数量</th>
            </tr>
"""
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_stats.get(severity, 0)
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                html += f"""
            <tr>
                <td>{emoji} {_esc(severity)}</td>
                <td>{_esc(count)}</td>
            </tr>
"""
            html += """
        </table>
"""
        
        # 扫描范围（已扫描 / 未纳入扫描及原因）
        discovered = stats.get('discovered_files', [])
        skipped = stats.get('skipped_files', [])
        if discovered or skipped:
            html += """
        <h2>📂 扫描范围</h2>
        <p>以下为本次扫描发现的代码文件与未纳入扫描的文件及原因，便于核对「为何只扫到少量文件」。</p>
        <table>
            <tr>
                <th>类型</th>
                <th>说明</th>
            </tr>
            <tr>
                <td><strong>已纳入扫描</strong></td>
                <td>扩展名为 .js / .jsx / .mjs / .ts / .tsx / .py 等（见扫描器支持列表）</td>
            </tr>
            <tr>
                <td><strong>未纳入扫描</strong></td>
                <td>扩展名不支持或命中忽略规则（如 .html、.sql、.json、测试目录等）</td>
            </tr>
        </table>
"""
            if discovered:
                html += f"""
        <p><strong>已扫描的代码文件（共 {len(discovered)} 个）</strong></p>
        <ul>
"""
                for p in discovered[:50]:
                    html += f"""
            <li><code>{_esc(p)}</code></li>
"""
                if len(discovered) > 50:
                    html += f"""
            <li>… 及其他 {len(discovered) - 50} 个</li>
"""
                html += """
        </ul>
"""
            if skipped:
                html += f"""
        <p><strong>未纳入扫描的文件（共 {len(skipped)} 个，仅列前 30 个）</strong></p>
        <ul>
"""
                for path, reason in skipped[:30]:
                    html += f"""
            <li><code>{_esc(path)}</code> — {_esc(reason)}</li>
"""
                if len(skipped) > 30:
                    html += f"""
            <li>… 及其他 {len(skipped) - 30} 个</li>
"""
                html += """
        </ul>
"""
        
        # 详细结果
        if results:
            html += """
        <h2>🔍 详细发现</h2>
"""
            for file_path, findings in results.items():
                html += f"""
        <div class="file-section">
            <h3>📄 {_esc(file_path)}</h3>
            <p><strong>问题数量</strong>: {len(findings)}</p>
"""
                
                # 按严重程度分组
                by_severity = {}
                for finding in findings:
                    severity = finding.get('severity', 'Medium')
                    if severity not in by_severity:
                        by_severity[severity] = []
                    by_severity[severity].append(finding)
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    if severity not in by_severity:
                        continue
                    
                    html += f"""
            <h4 class="{severity.lower()}">{severity} 级别</h4>
"""
                    for finding in by_severity[severity]:
                        html += f"""
            <div class="finding {severity.lower()}">
                <p><strong>第 {_esc(finding.get('line', '?'))} 行</strong> - <code>{_esc(finding.get('type', 'Unknown'))}</code></p>
                <p>{_esc(finding.get('details', 'No details'))}</p>
"""
                        # TDD 7.1：关联位置（污点来源等）
                        related = finding.get("related_locations") or []
                        if related:
                            html += """
                <p><strong>关联位置：</strong></p>
                <ul>
"""
                            for loc in related:
                                start = loc.get("start_line", "?")
                                msg = loc.get("message", "")
                                html += f"""
                    <li>第 {_esc(start)} 行{": " + _esc(msg) if msg else ""}</li>
"""
                            html += """
                </ul>
"""
                        if finding.get('content'):
                            html += f"""
                <pre><code>{_esc(finding['content'])}</code></pre>
"""
                        html += """
            </div>
"""
                
                html += """
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html
    
    def generate_sarif(self, results: Dict[str, List[Dict]], stats: Dict) -> str:
        """
        生成 SARIF 格式报告（GitHub 支持）
        
        Args:
            results: 扫描结果字典
            stats: 统计信息
            
        Returns:
            SARIF 格式的报告字符串
        """
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Aegis Security Scanner",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/your-repo/aegis-ai"
                    }
                },
                "results": self._convert_to_sarif_results(results)
            }]
        }
        
        return json.dumps(sarif, indent=2, ensure_ascii=False)
    
    def _convert_to_sarif_results(self, results: Dict[str, List[Dict]]) -> List[Dict]:
        """
        将扫描结果转换为 SARIF 格式
        
        Args:
            results: 扫描结果字典
            
        Returns:
            SARIF 格式的结果列表
        """
        sarif_results = []
        
        severity_map = {
            'Critical': 'error',
            'High': 'error',
            'Medium': 'warning',
            'Low': 'note'
        }
        
        for file_path, findings in results.items():
            for finding in findings:
                sarif_result = {
                    "ruleId": finding.get('type', 'UNKNOWN'),
                    "level": severity_map.get(finding.get('severity', 'Medium'), 'warning'),
                    "message": {
                        "text": finding.get('details', 'No details')
                    },
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": file_path
                            },
                            "region": {
                                "startLine": finding.get('line', 1),
                                "startColumn": 1
                            }
                        }
                    }]
                }
                sarif_results.append(sarif_result)
        
        return sarif_results
    
    def generate_html_enhanced(self, results: Dict[str, List[Dict]], stats: Dict) -> str:
        """
        生成增强版 HTML 报告（包含 RAG 修复建议）
        
        Args:
            results: 扫描结果字典（已增强）
            stats: 统计信息
            
        Returns:
            增强版 HTML 格式的报告字符串
        """
        # 处理扫描时间显示
        scan_time = stats.get('scan_time', 0)
        if isinstance(scan_time, (int, float)):
            scan_time_display = f"{scan_time:.2f} 秒"
        else:
            scan_time_display = str(scan_time)
        
        html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>安全扫描报告（增强版） - {_esc(self.project_name)}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #4CAF50;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background-color: #4CAF50;
            color: white;
        }}
        .critical {{ color: #d32f2f; font-weight: bold; }}
        .high {{ color: #f57c00; font-weight: bold; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #1976d2; }}
        .file-section {{
            margin: 20px 0;
            padding: 15px;
            background-color: #f9f9f9;
            border-left: 4px solid #4CAF50;
        }}
        .finding {{
            margin: 10px 0;
            padding: 15px;
            background-color: #fff;
            border-left: 3px solid #ccc;
            border-radius: 4px;
        }}
        .finding.critical {{ border-left-color: #d32f2f; background-color: #ffebee; }}
        .finding.high {{ border-left-color: #f57c00; background-color: #fff3e0; }}
        .finding.medium {{ border-left-color: #fbc02d; background-color: #fffde7; }}
        .finding.low {{ border-left-color: #1976d2; background-color: #e3f2fd; }}
        code {{
            background-color: #f4f4f4;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }}
        pre {{
            background-color: #f4f4f4;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
        .remediation {{
            margin-top: 10px;
            padding: 10px;
            background-color: #e8f5e9;
            border-radius: 4px;
            border-left: 3px solid #4CAF50;
        }}
        .remediation h5 {{
            margin: 0 0 8px 0;
            color: #2e7d32;
        }}
        .remediation ul {{
            margin: 5px 0;
            padding-left: 20px;
        }}
        .remediation a {{
            color: #1976d2;
            text-decoration: none;
        }}
        .remediation a:hover {{
            text-decoration: underline;
        }}
        .cve-info {{
            margin-top: 10px;
            padding: 8px;
            background-color: #fff8e1;
            border-radius: 4px;
            font-size: 0.9em;
        }}
        .badge {{
            display: inline-block;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            margin-right: 5px;
        }}
        .badge-cwe {{ background-color: #e1f5fe; color: #0277bd; }}
        .badge-rag {{ background-color: #f3e5f5; color: #7b1fa2; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔒 安全扫描报告（增强版） - {_esc(self.project_name)}</h1>
        <p><strong>扫描时间</strong>: {_esc(self.scan_time)}</p>
        <p><span class="badge badge-rag">🤖 RAG 增强</span> 本报告包含智能修复建议</p>
        
        <h2>📊 扫描摘要</h2>
        <table>
            <tr>
                <th>指标</th>
                <th>数量</th>
            </tr>
            <tr>
                <td>总文件数</td>
                <td>{_esc(stats.get('total_files', 0))}</td>
            </tr>
            <tr>
                <td>扫描文件数</td>
                <td>{_esc(stats.get('scanned_files', 0))}</td>
            </tr>
            <tr>
                <td>有问题文件数</td>
                <td>{_esc(stats.get('files_with_issues', 0))}</td>
            </tr>
            <tr>
                <td>总问题数</td>
                <td>{_esc(stats.get('total_issues', 0))}</td>
            </tr>
            <tr>
                <td>扫描耗时</td>
                <td>{_esc(scan_time_display)}</td>
            </tr>
        </table>
"""
        
        # 严重程度统计
        severity_stats = stats.get('severity_stats', {})
        if severity_stats:
            html += """
        <h2>🎯 严重程度统计</h2>
        <table>
            <tr>
                <th>严重程度</th>
                <th>数量</th>
            </tr>
"""
            for severity in ['Critical', 'High', 'Medium', 'Low']:
                count = severity_stats.get(severity, 0)
                emoji = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
                html += f"""
            <tr>
                <td>{emoji} {_esc(severity)}</td>
                <td>{_esc(count)}</td>
            </tr>
"""
            html += """
        </table>
"""
        
        # 基准评估（阶段四：当 stats 含 recall/precision/f1 时显示）
        if any(k in stats for k in ("recall", "precision", "f1")):
            recall = stats.get("recall")
            precision = stats.get("precision")
            f1 = stats.get("f1")
            html += """
        <h2>📈 基准评估</h2>
        <table>
            <tr><th>指标</th><th>值</th></tr>
"""
            if recall is not None:
                html += f"            <tr><td>检测率 (Recall)</td><td>{_esc(f'{recall:.1%}' if isinstance(recall, (int, float)) else recall)}</td></tr>\n"
            if precision is not None:
                html += f"            <tr><td>精确率 (Precision)</td><td>{_esc(f'{precision:.1%}' if isinstance(precision, (int, float)) else precision)}</td></tr>\n"
            if f1 is not None:
                html += f"            <tr><td>F1 Score</td><td>{_esc(f'{f1:.2f}' if isinstance(f1, (int, float)) else f1)}</td></tr>\n"
            html += """
        </table>
"""
        
        # 详细结果（增强版）
        if results:
            html += """
        <h2>🔍 详细发现（含修复建议）</h2>
"""
            for file_path, findings in results.items():
                html += f"""
        <div class="file-section">
            <h3>📄 {_esc(file_path)}</h3>
            <p><strong>问题数量</strong>: {len(findings)}</p>
"""
                
                # 按严重程度分组
                by_severity = {}
                for finding in findings:
                    severity = finding.get('severity', 'Medium')
                    if severity not in by_severity:
                        by_severity[severity] = []
                    by_severity[severity].append(finding)
                
                for severity in ['Critical', 'High', 'Medium', 'Low']:
                    if severity not in by_severity:
                        continue
                    
                    html += f"""
            <h4 class="{severity.lower()}">{severity} 级别</h4>
"""
                    for finding in by_severity[severity]:
                        html += f"""
            <div class="finding {severity.lower()}">
                <p><strong>第 {_esc(finding.get('line', '?'))} 行</strong> - <code>{_esc(finding.get('type', 'Unknown'))}</code></p>
                <p>{_esc(finding.get('details', 'No details'))}</p>
"""
                        # TDD 7.1：关联位置（污点来源等）
                        related = finding.get("related_locations") or []
                        if related:
                            html += """
                <p><strong>关联位置：</strong></p>
                <ul>
"""
                            for loc in related:
                                start = loc.get("start_line", "?")
                                msg = loc.get("message", "")
                                html += f"""
                    <li>第 {_esc(start)} 行{": " + _esc(msg) if msg else ""}</li>
"""
                            html += """
                </ul>
"""
                        if finding.get('content'):
                            html += f"""
                <pre><code>{_esc(finding['content'])}</code></pre>
"""
                        
                        # 添加修复建议（RAG 增强）
                        remediation = finding.get('remediation', {})
                        if remediation:
                            cwe = remediation.get('cwe', '')
                            description = remediation.get('description', '')
                            suggestions = remediation.get('suggestions', [])
                            references = remediation.get('references', [])
                            
                            html += f"""
                <div class="remediation">
                    <h5>💡 修复建议</h5>
"""
                            if cwe:
                                html += f'<span class="badge badge-cwe">{_esc(cwe)}</span>'
                            
                            if description:
                                html += f"<p><em>{_esc(description)}</em></p>"
                            
                            if suggestions:
                                html += "<ul>"
                                for suggestion in suggestions:
                                    html += f"<li>{_esc(suggestion)}</li>"
                                html += "</ul>"
                            
                            if references:
                                html += "<p><strong>参考链接：</strong></p><ul>"
                                for ref in references:
                                    html += f'<li><a href="{_esc(ref)}" target="_blank">{_esc(ref)}</a></li>'
                                html += "</ul>"
                            
                            html += """
                </div>
"""
                        
                        # 添加相关 CVE 信息
                        related_cves = finding.get('related_cves', [])
                        if related_cves:
                            html += """
                <div class="cve-info">
                    <strong>📋 相关 CVE：</strong>
                    <ul>
"""
                            for cve in related_cves:
                                html += f'<li><strong>{_esc(cve.get("cve_id", ""))}</strong> (相关度: {_esc(cve.get("relevance", 0))}) - {_esc(cve.get("description", ""))}</li>'
                            html += """
                    </ul>
                </div>
"""
                        
                        html += """
            </div>
"""
                
                html += """
        </div>
"""
        
        html += """
    </div>
</body>
</html>
"""
        
        return html


if __name__ == '__main__':
    # 测试代码
    generator = ReportGenerator("Test Project")
    
    # 模拟结果
    test_results = {
        "test.py": [
            {
                "line": 10,
                "type": "SQL Injection Risk",
                "severity": "High",
                "details": "发现 SQL 字符串拼接",
                "content": "query = \"SELECT * FROM users WHERE id = \" + user_id"
            }
        ]
    }
    
    test_stats = {
        "total_files": 10,
        "scanned_files": 10,
        "files_with_issues": 1,
        "total_issues": 1,
        "scan_time": 1.5,
        "severity_stats": {"High": 1}
    }
    
    print("JSON 格式:")
    print(generator.generate_json(test_results, test_stats))
    print("\n" + "="*70 + "\n")
    
    print("Markdown 格式:")
    print(generator.generate_markdown(test_results, test_stats))
