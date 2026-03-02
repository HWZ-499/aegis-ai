"""
taint_enhancer.py - 污点分析增强器

将完整的 Source → Sink 污点分析集成到扫描流程中。

功能：
- 对扫描发现进行污点路径追踪
- 提供详细的数据流路径信息
- 增强报告的可信度和可操作性

使用方式：
    from scanner.taint_enhancer import TaintEnhancer
    
    enhancer = TaintEnhancer(language="javascript")
    enhanced_findings = enhancer.enhance_findings(findings, code, file_path)
"""

from __future__ import annotations

import sys
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

# 添加项目路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
_project_root = os.path.dirname(os.path.dirname(_current_dir))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# 导入污点分析模块
try:
    from src.analysis.taint import TaintAnalyzer, TaintGraph, TaintPath
    TAINT_ANALYSIS_AVAILABLE = True
except ImportError:
    TAINT_ANALYSIS_AVAILABLE = False
    TaintAnalyzer = None
    TaintGraph = None
    TaintPath = None


class TaintEnhancer:
    """
    污点分析增强器。
    
    将污点分析结果与现有扫描发现进行关联，
    提供详细的数据流路径信息。
    
    使用示例：
        enhancer = TaintEnhancer(language="javascript")
        
        # 单文件分析
        taint_findings = enhancer.analyze_file(file_path)
        
        # 增强现有发现
        enhanced = enhancer.enhance_findings(findings, code, file_path)
    """
    
    def __init__(self, language: str = "javascript"):
        """
        初始化污点增强器。
        
        Args:
            language: 目标语言
        """
        self.language = language.lower()
        self._analyzer: Optional[TaintAnalyzer] = None
        
        if TAINT_ANALYSIS_AVAILABLE:
            self._analyzer = TaintAnalyzer(language=self.language)
    
    @property
    def is_available(self) -> bool:
        """检查污点分析是否可用"""
        return TAINT_ANALYSIS_AVAILABLE and self._analyzer is not None
    
    def analyze_file(self, file_path: Path) -> List[Dict]:
        """
        对单个文件进行污点分析。
        
        Args:
            file_path: 文件路径
        
        Returns:
            发现的污点路径漏洞列表
        """
        if not self.is_available:
            return []
        
        try:
            # 重置分析器
            self._analyzer.reset()
            
            # 执行污点分析
            findings = self._analyzer.analyze_file(file_path)
            
            # 转换为标准格式
            return [self._convert_finding(f) for f in findings]
            
        except Exception as e:
            print(f"⚠️ 污点分析失败 {file_path}: {e}")
            return []
    
    def analyze_code(self, code: str, file_path: str = "") -> List[Dict]:
        """
        对代码字符串进行污点分析。
        
        Args:
            code: 源代码
            file_path: 文件路径（可选）
        
        Returns:
            发现的污点路径漏洞列表
        """
        if not self.is_available:
            return []
        
        try:
            # 重置分析器
            self._analyzer.reset()
            
            # 执行污点分析
            findings = self._analyzer.analyze_code(code, file_path)
            
            # 转换为标准格式
            return [self._convert_finding(f) for f in findings]
            
        except Exception as e:
            print(f"⚠️ 污点分析失败: {e}")
            return []
    
    def enhance_findings(
        self,
        findings: List[Dict],
        code: str,
        file_path: str = ""
    ) -> List[Dict]:
        """
        增强现有扫描发现，添加污点路径信息。
        
        Args:
            findings: 现有扫描发现
            code: 源代码
            file_path: 文件路径
        
        Returns:
            增强后的发现列表
        """
        if not self.is_available or not findings:
            return findings
        
        try:
            # 执行污点分析
            self._analyzer.reset()
            self._analyzer.analyze_code(code, file_path)
            
            # 获取污点图
            graph = self._analyzer.get_graph()
            
            # 增强每个发现
            enhanced = []
            for finding in findings:
                enhanced_finding = finding.copy()
                
                # 尝试找到相关的污点路径
                line = finding.get('line', 0)
                taint_info = self._find_related_taint_path(graph, line, file_path)
                
                if taint_info:
                    enhanced_finding['taint_analysis'] = taint_info
                    # 如果找到污点路径，提升置信度
                    if taint_info.get('has_taint_path'):
                        enhanced_finding['confidence'] = 'high'
                        enhanced_finding['taint_path'] = taint_info.get('path_string', '')
                
                enhanced.append(enhanced_finding)
            
            return enhanced
            
        except Exception as e:
            print(f"⚠️ 污点增强失败: {e}")
            return findings
    
    def _find_related_taint_path(
        self,
        graph: TaintGraph,
        line: int,
        file_path: str
    ) -> Optional[Dict]:
        """
        查找与指定行号相关的污点路径。
        
        Args:
            graph: 污点图
            line: 行号
            file_path: 文件路径
        
        Returns:
            污点信息字典
        """
        try:
            # 查找所有路径
            paths = graph.find_paths_to_sinks()
            
            # 找到与行号相关的路径
            for path in paths:
                if path.sink_node and path.sink_node.line == line:
                    return {
                        'has_taint_path': True,
                        'source': path.source_node.name if path.source_node else '',
                        'source_line': path.source_node.line if path.source_node else 0,
                        'sink': path.sink_node.name if path.sink_node else '',
                        'sink_line': line,
                        'path_length': len(path),
                        'path_string': path.to_string(),
                        'is_sanitized': path.is_sanitized,
                    }
            
            # 检查行号附近是否有被污染的节点
            for node in graph.get_tainted_nodes():
                if node.file_path == file_path and abs(node.line - line) <= 3:
                    return {
                        'has_taint_path': False,
                        'nearby_tainted_var': node.name,
                        'nearby_tainted_line': node.line,
                    }
            
            return None
            
        except Exception:
            return None
    
    def _convert_finding(self, finding: Any) -> Dict:
        """
        将 TaintFinding 转换为标准字典格式。
        
        Args:
            finding: TaintFinding 对象
        
        Returns:
            标准格式的字典
        """
        return {
            'type': finding.vuln_type,
            'severity': finding.severity,
            'confidence': 'high' if finding.confidence > 0.7 else 'medium',
            'line': finding.line,
            'file': finding.file_path,
            'description': finding.description,
            'cwe': finding.cwe,
            'remediation': finding.remediation,
            'source': 'taint_analysis',
            'taint_path': finding.taint_path.to_string() if finding.taint_path else '',
            'taint_details': finding.taint_path.to_dict() if finding.taint_path else {},
        }
    
    def get_stats(self) -> Dict[str, Any]:
        """获取污点分析统计信息"""
        if not self.is_available or not self._analyzer:
            return {'available': False}
        
        graph = self._analyzer.get_graph()
        return {
            'available': True,
            'graph_stats': graph.get_stats(),
        }


def enhance_scan_results(
    results: Dict[str, List[Dict]],
    project_path: str,
    language: str = "javascript"
) -> Dict[str, List[Dict]]:
    """
    批量增强扫描结果。
    
    Args:
        results: 扫描结果字典（文件路径 -> 发现列表）
        project_path: 项目根目录
        language: 语言
    
    Returns:
        增强后的结果
    """
    if not TAINT_ANALYSIS_AVAILABLE:
        return results
    
    enhancer = TaintEnhancer(language=language)
    enhanced_results = {}
    
    project_root = Path(project_path)
    
    for rel_path, findings in results.items():
        if not findings:
            enhanced_results[rel_path] = findings
            continue
        
        file_path = project_root / rel_path
        if not file_path.exists():
            enhanced_results[rel_path] = findings
            continue
        
        # 读取文件内容
        try:
            code = file_path.read_text(encoding='utf-8', errors='ignore')
            
            # 检测语言
            ext = file_path.suffix.lower()
            if ext in ('.js', '.jsx', '.mjs', '.ts', '.tsx'):
                file_lang = 'javascript'
            elif ext == '.py':
                file_lang = 'python'
            else:
                file_lang = language
            
            # 创建对应语言的增强器
            if file_lang != enhancer.language:
                enhancer = TaintEnhancer(language=file_lang)
            
            # 增强发现
            enhanced_findings = enhancer.enhance_findings(findings, code, str(file_path))
            enhanced_results[rel_path] = enhanced_findings
            
        except Exception as e:
            print(f"⚠️ 增强失败 {rel_path}: {e}")
            enhanced_results[rel_path] = findings
    
    return enhanced_results


__all__ = [
    "TaintEnhancer",
    "enhance_scan_results",
    "TAINT_ANALYSIS_AVAILABLE",
]
