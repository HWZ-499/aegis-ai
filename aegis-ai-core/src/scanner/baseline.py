# baseline.py - Baseline 与抑制
"""
Baseline 文件格式与差分逻辑，用于「仅报新增」场景。
支持从 .aegis-baseline.json 加载、保存、与当前 findings 做 diff。
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from pydantic import BaseModel, Field


class BaselineFinding(BaseModel):
    """Baseline 中的单条记录，用于匹配 finding。"""

    rule_id: str = Field(alias="rule_id")
    file_path: str = Field(alias="file_path")
    line: int = Field(alias="line")
    fingerprint: str = Field(default="", alias="fingerprint")

    class Config:
        populate_by_name = True


def _fingerprint(finding: dict, project_root: Path | None = None) -> str:
    """基于 rule_id + file_path + line 生成稳定指纹。"""
    rule_id = finding.get("type") or finding.get("rule_id") or "UNKNOWN"
    file_path = finding.get("file") or finding.get("file_path") or ""
    if project_root and file_path:
        try:
            p = Path(file_path)
            if p.is_absolute():
                file_path = str(p.relative_to(project_root)) if project_root in p.parents else p.name
            else:
                file_path = str(Path(file_path).as_posix())
        except (ValueError, TypeError):
            file_path = str(file_path).replace("\\", "/")
    line = finding.get("line", 0)
    raw = f"{rule_id}|{file_path}|{line}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _finding_to_baseline_entry(f: dict, project_root: Path | None = None) -> dict:
    """将 finding 转为 baseline 条目的字典。"""
    fp = _fingerprint(f, project_root)
    file_path = f.get("file") or f.get("file_path") or ""
    if project_root and file_path:
        try:
            p = Path(file_path)
            if p.is_absolute():
                file_path = str(p.relative_to(project_root))
            file_path = str(Path(file_path).as_posix())
        except (ValueError, TypeError):
            file_path = str(file_path).replace("\\", "/")
    return {
        "rule_id": f.get("type") or f.get("rule_id") or "UNKNOWN",
        "file_path": file_path,
        "line": int(f.get("line", 0)),
        "fingerprint": fp,
    }


class Baseline:
    """Baseline 集合：加载、保存、判断包含、求新增。"""

    def __init__(self, entries: list[BaselineFinding] | None = None) -> None:
        self._by_fingerprint: dict[str, BaselineFinding] = {}
        for e in entries or []:
            self._by_fingerprint[e.fingerprint] = e

    @classmethod
    def load(cls, path: Path) -> Baseline:
        """从 JSON 文件加载 baseline。"""
        if not path.exists():
            return cls([])
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return cls([])
        if not isinstance(data, dict):
            return cls([])
        entries_list = data.get("findings", data) if isinstance(data.get("findings"), list) else []
        if not isinstance(entries_list, list):
            entries_list = []
        entries: list[BaselineFinding] = []
        for item in entries_list:
            if isinstance(item, dict):
                try:
                    entries.append(BaselineFinding.model_validate(item))
                except Exception:
                    continue
        return cls(entries)

    def save(self, path: Path, project_root: Path | None = None) -> None:
        """将当前条目写入 JSON 文件。"""
        path.parent.mkdir(parents=True, exist_ok=True)
        entries = [e.model_dump(by_alias=True) for e in self._by_fingerprint.values()]
        payload = {"version": 1, "findings": entries}
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    def contains(self, finding: dict, project_root: Path | None = None) -> bool:
        """判断某 finding 是否已在 baseline 中。"""
        fp = _fingerprint(finding, project_root)
        return fp in self._by_fingerprint

    def diff(
        self,
        results: dict[str, list[dict]],
        project_root: Path | None = None,
    ) -> dict[str, list[dict]]:
        """返回不在 baseline 中的 findings（按文件分组）。"""
        out: dict[str, list[dict]] = {}
        for file_path, findings in results.items():
            new_list = [f for f in findings if not self.contains(f, project_root)]
            if new_list:
                out[file_path] = new_list
        return out

    def add_findings(
        self,
        results: dict[str, list[dict]],
        project_root: Path | None = None,
    ) -> None:
        """将一批 findings 加入 baseline（去重）。"""
        for findings in results.values():
            for f in findings:
                entry = _finding_to_baseline_entry(f, project_root)
                fp = entry["fingerprint"]
                if fp not in self._by_fingerprint:
                    self._by_fingerprint[fp] = BaselineFinding.model_validate(entry)


# ---------------------------------------------------------------------------
# 行级抑制：aegis-ignore / # aegis-ignore / aegis-ignore: RULE_ID
# ---------------------------------------------------------------------------

AEGIS_IGNORE_RE = re.compile(
    r"aegis-ignore(?:\s*:\s*([A-Za-z0-9_]+))?",
    re.IGNORECASE,
)


def _line_has_suppress(line: str, rule_id: str | None) -> bool:
    """该行是否包含 aegis-ignore，且若指定了 rule_id 则匹配规则。"""
    m = AEGIS_IGNORE_RE.search(line)
    if not m:
        return False
    specified = m.group(1)
    if not specified:
        return True  # 抑制该行所有
    return specified.strip().upper() == (rule_id or "").upper()


def filter_suppressed_findings(findings: list[dict], source: str) -> list[dict]:
    """
    根据源码行内 aegis-ignore 注释过滤 findings。
    source: 文件完整源码；findings 中 line 为 1-based。
    """
    if not source or not findings:
        return findings
    lines = source.splitlines()
    out: list[dict] = []
    for f in findings:
        line_no = int(f.get("line", 0))
        if line_no < 1 or line_no > len(lines):
            out.append(f)
            continue
        line_text = lines[line_no - 1]
        rule_id = f.get("type") or f.get("rule_id")
        if _line_has_suppress(line_text, rule_id):
            continue
        out.append(f)
    return out
