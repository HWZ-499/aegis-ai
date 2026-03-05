"""
models.py — 共享 Pydantic 数据模型。

所有模块之间传递的核心数据结构在此定义，
消除裸 dict 传递和字段名不一致问题。
"""

from __future__ import annotations

from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class RelatedLocation(BaseModel):
    """漏洞关联位置（如污点传播中间节点）。"""

    file_path: str
    line: int
    column: int = 0
    message: str = ""


class TaintStep(BaseModel):
    """污点传播路径中的单个步骤。"""

    node_type: str = ""
    variable: str = ""
    file_path: str = ""
    line: int = 0
    column: int = 0
    description: str = ""


class Finding(BaseModel):
    """
    安全扫描发现（统一数据模型）。

    所有规则引擎、污点分析器、扫描器的产出均应转换为此结构。
    """

    rule_id: str = Field(description="规则唯一标识，如 SQL_INJECTION")
    vuln_type: str = Field(description="漏洞类型的人类可读名称")
    severity: Literal["Critical", "High", "Medium", "Low"] = Field(default="Medium")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    file_path: str = Field(default="")
    line: int = Field(default=0, ge=0)
    column: int = Field(default=0, ge=0)
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    message: str = Field(default="")
    details: str = Field(default="")
    fix_suggestion: Optional[str] = None

    related_locations: List[RelatedLocation] = Field(default_factory=list)
    taint_path: Optional[List[TaintStep]] = None

    cwe_id: Optional[str] = Field(default=None, description="CWE 编号，如 CWE-89")

    def to_legacy_dict(self) -> Dict[str, Any]:
        """
        向后兼容：转换为旧版 dict 格式。

        Returns:
            兼容现有代码的 dict 结构。
        """
        d: Dict[str, Any] = {
            "type": self.vuln_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "line": self.line,
            "column": self.column,
            "details": self.details or self.message,
            "file_path": self.file_path,
        }
        if self.fix_suggestion:
            d["fix_suggestion"] = self.fix_suggestion
        if self.end_line is not None:
            d["end_line"] = self.end_line
        if self.end_column is not None:
            d["end_column"] = self.end_column
        if self.cwe_id:
            d["cwe_id"] = self.cwe_id
        if self.related_locations:
            d["related_locations"] = [rl.model_dump() for rl in self.related_locations]
        if self.taint_path:
            d["taint_path"] = [ts.model_dump() for ts in self.taint_path]
        return d

    @classmethod
    def from_legacy_dict(cls, d: Dict[str, Any]) -> "Finding":
        """
        从旧版 dict 格式构建 Finding。

        Args:
            d: 旧版 finding dict。

        Returns:
            Finding 实例。
        """
        severity_raw = d.get("severity", "Medium")
        valid_severities = {"Critical", "High", "Medium", "Low"}
        severity = severity_raw if severity_raw in valid_severities else "Medium"

        return cls(
            rule_id=d.get("rule_id", d.get("type", "UNKNOWN")),
            vuln_type=d.get("type", d.get("vuln_type", d.get("rule_id", "UNKNOWN"))),
            severity=severity,
            confidence=d.get("confidence", 0.5),
            file_path=d.get("file_path", ""),
            line=d.get("line", 0),
            column=d.get("column", 0),
            end_line=d.get("end_line"),
            end_column=d.get("end_column"),
            message=d.get("message", d.get("details", "")),
            details=d.get("details", d.get("message", "")),
            fix_suggestion=d.get("fix_suggestion"),
            cwe_id=d.get("cwe_id"),
        )


class ScanResult(BaseModel):
    """单个文件的扫描结果。"""

    file_path: str
    language: str = ""
    findings: List[Finding] = Field(default_factory=list)
    scan_time_ms: float = 0.0
    error: Optional[str] = None


class AuditResponse(BaseModel):
    """/api/audit 端点的响应模型。"""

    reply: str = ""
    mode: str = "audit"
    filename: str = ""
    findings_count: int = 0
    severity_count: Dict[str, int] = Field(default_factory=dict)
    used_ai: bool = False
    scan_time_ms: float = 0.0


class ChatResponse(BaseModel):
    """/api/chat 端点的响应模型。"""

    reply: str = ""
    mode: str = "chat"
    distance: float = 0.0
