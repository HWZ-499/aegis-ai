"""
models.py — 共享 Pydantic 数据模型。

所有模块之间传递的核心数据结构在此定义，
消除裸 dict 传递和字段名不一致问题。
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def _coerce_location_coordinate(value: Any) -> int:
    """Coerce legacy related-location coordinates to non-negative integers."""
    if not isinstance(value, (int, float, str)):
        return 0
    try:
        return max(int(value), 0)
    except (TypeError, ValueError):
        return 0


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
    支持 extra 字段以兼容规则层产出的 source_expr、sink_expr 等。
    """

    model_config = ConfigDict(extra="allow")

    rule_id: str = Field(description="规则唯一标识，如 SQL_INJECTION")
    vuln_type: str = Field(description="漏洞类型的人类可读名称")
    severity: Literal["Critical", "High", "Medium", "Low"] = Field(default="Medium")
    confidence: float | str = Field(default=0.5)

    file_path: str = Field(default="")
    line: int = Field(default=0, ge=0)
    column: int = Field(default=0, ge=0)
    end_line: int | None = None
    end_column: int | None = None
    start_line: int | None = None
    start_character: int | None = None
    end_character: int | None = None

    message: str = Field(default="")
    details: str = Field(default="")
    fix_suggestion: str | None = None

    related_locations: list[RelatedLocation] = Field(default_factory=list)
    taint_path: list[TaintStep] | None = None

    cwe_id: str | None = Field(default=None, description="CWE 编号，如 CWE-89")

    def to_legacy_dict(self) -> dict[str, Any]:
        """
        向后兼容：转换为旧版 dict 格式。

        Returns:
            兼容现有代码的 dict 结构。
        """
        d: dict[str, Any] = {
            "type": self.vuln_type,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "line": self.line,
            "column": self.column,
            "details": self.details or self.message,
            "file_path": self.file_path,
            "file": self.file_path,
        }
        if self.fix_suggestion:
            d["fix_suggestion"] = self.fix_suggestion
        if self.end_line is not None:
            d["end_line"] = self.end_line
        if self.end_column is not None:
            d["end_column"] = self.end_column
        if self.start_line is not None:
            d["start_line"] = self.start_line
        if self.start_character is not None:
            d["start_character"] = self.start_character
        if self.end_character is not None:
            d["end_character"] = self.end_character
        if self.cwe_id:
            d["cwe_id"] = self.cwe_id
        if self.related_locations:
            d["related_locations"] = [
                rl.model_dump() if hasattr(rl, "model_dump") else rl for rl in self.related_locations
            ]
        if self.taint_path:
            d["taint_path"] = [ts.model_dump() if hasattr(ts, "model_dump") else ts for ts in self.taint_path]
        # 透传 extra 字段（source_expr、sink_expr、taint_var 等）
        extra = getattr(self, "__pydantic_extra__", None) or {}
        for k, v in extra.items():
            if k not in d:
                d[k] = v
        return d

    @classmethod
    def from_legacy_dict(cls, d: dict[str, Any]) -> Finding:
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

        conf_raw = d.get("confidence", 0.5)
        if isinstance(conf_raw, str):
            conf_map = {"high": 0.9, "medium": 0.5, "low": 0.3}
            confidence = conf_map.get(conf_raw.lower(), 0.5)
        else:
            confidence = conf_raw if isinstance(conf_raw, (int, float)) else 0.5

        rl_raw = d.get("related_locations", [])
        related_locations: list[RelatedLocation] = []
        for item in rl_raw if isinstance(rl_raw, list) else []:
            if isinstance(item, dict):
                raw_line = item.get("start_line", item.get("line", 0))
                raw_column = item.get("start_character", item.get("column", 0))
                related_locations.append(
                    RelatedLocation(
                        file_path=str(item.get("file_path", item.get("file", ""))),
                        line=_coerce_location_coordinate(raw_line),
                        column=_coerce_location_coordinate(raw_column),
                        message=str(item.get("message", "")),
                    )
                )

        base = {
            "rule_id": d.get("rule_id", d.get("type", "UNKNOWN")),
            "vuln_type": d.get("type", d.get("vuln_type", d.get("rule_id", "UNKNOWN"))),
            "severity": severity,
            "confidence": confidence,
            "file_path": d.get("file_path", d.get("file", "")),
            "line": d.get("line", 0),
            "column": d.get("column", 0),
            "end_line": d.get("end_line"),
            "end_column": d.get("end_column"),
            "start_line": d.get("start_line"),
            "start_character": d.get("start_character"),
            "end_character": d.get("end_character"),
            "message": d.get("message", d.get("details", "")),
            "details": d.get("details", d.get("message", "")),
            "fix_suggestion": d.get("fix_suggestion"),
            "cwe_id": d.get("cwe_id"),
            "related_locations": related_locations,
        }
        known_keys = set(cls.model_fields.keys()) | {"type", "file", "vuln_type"}
        extra = {k: v for k, v in d.items() if k not in known_keys}
        return cls(**base, **extra)


class ScanResult(BaseModel):
    """单个文件的扫描结果。"""

    file_path: str
    language: str = ""
    findings: list[Finding] = Field(default_factory=list)
    scan_time_ms: float = 0.0
    error: str | None = None


class AuditResponse(BaseModel):
    """/api/audit 端点的响应模型。"""

    reply: str = ""
    mode: str = "audit"
    filename: str = ""
    findings_count: int = 0
    severity_count: dict[str, int] = Field(default_factory=dict)
    used_ai: bool = False
    scan_time_ms: float = 0.0


class ChatResponse(BaseModel):
    """/api/chat 端点的响应模型。"""

    reply: str = ""
    mode: str = "chat"
    distance: float = 0.0
