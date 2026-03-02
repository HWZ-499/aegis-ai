"""
analysis.analyzers

按语言划分的分析器命名空间：
- PythonAnalyzer: 处理 Python 源码（使用内置 ast + Tree-sitter TaintAnalyzer）
- JavaScriptAnalyzer: 处理 JS/TS 源码（使用 Tree-sitter + TaintAnalyzer）
- PhpAnalyzer: 处理 PHP 源码（使用 Tree-sitter + PhpTaintGraph）
"""

from .python_analyzer import PythonAnalyzer
from .javascript_analyzer import JavaScriptAnalyzer
from .php_analyzer import PhpAnalyzer

__all__ = ["PythonAnalyzer", "JavaScriptAnalyzer", "PhpAnalyzer"]

