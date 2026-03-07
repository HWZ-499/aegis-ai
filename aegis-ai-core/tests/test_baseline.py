# test_baseline.py - Baseline 与抑制测试
"""P3-1: Baseline 加载/保存/diff 与行级 aegis-ignore 抑制。"""

import json
from pathlib import Path

import pytest

from src.scanner.baseline import (
    Baseline,
    BaselineFinding,
    filter_suppressed_findings,
    _fingerprint,
    _finding_to_baseline_entry,
)


def test_baseline_finding_model() -> None:
    """BaselineFinding 可正确反序列化。"""
    e = BaselineFinding.model_validate({
        "rule_id": "SQL_INJECTION",
        "file_path": "app/main.py",
        "line": 10,
        "fingerprint": "abc123",
    })
    assert e.rule_id == "SQL_INJECTION"
    assert e.file_path == "app/main.py"
    assert e.line == 10
    assert e.fingerprint == "abc123"


def test_fingerprint_stable() -> None:
    """相同 finding 产生相同 fingerprint。"""
    f = {"type": "XSS_RISK", "file": "x.js", "line": 5}
    a = _fingerprint(f, None)
    b = _fingerprint(f, None)
    assert a == b


def test_baseline_empty_load(tmp_path: Path) -> None:
    """空路径或不存在文件加载得到空 Baseline。"""
    assert len(Baseline.load(tmp_path / "nonexistent.json")._by_fingerprint) == 0
    b = Baseline.load(tmp_path)
    assert len(b._by_fingerprint) == 0


def test_baseline_save_and_load(tmp_path: Path) -> None:
    """保存后能正确加载。"""
    b = Baseline([
        BaselineFinding(rule_id="R1", file_path="a.py", line=1, fingerprint="fp1"),
        BaselineFinding(rule_id="R2", file_path="b.js", line=2, fingerprint="fp2"),
    ])
    path = tmp_path / "base.json"
    b.save(path)
    assert path.exists()
    loaded = Baseline.load(path)
    assert len(loaded._by_fingerprint) == 2
    assert "fp1" in loaded._by_fingerprint


def test_baseline_contains_and_diff(tmp_path: Path) -> None:
    """contains 与 diff 行为正确。"""
    b = Baseline()
    f1 = {"type": "SQL_INJECTION", "file": "app.py", "line": 10}
    fp1 = _fingerprint(f1, None)
    b._by_fingerprint[fp1] = BaselineFinding(
        rule_id="SQL_INJECTION", file_path="app.py", line=10, fingerprint=fp1
    )
    assert b.contains(f1, None) is True
    f2 = {"type": "XSS_RISK", "file": "other.js", "line": 1}
    assert b.contains(f2, None) is False
    results = {"app.py": [f1], "other.js": [f2]}
    diffed = b.diff(results, None)
    assert "app.py" not in diffed
    assert "other.js" in diffed and len(diffed["other.js"]) == 1


def test_baseline_add_findings(tmp_path: Path) -> None:
    """add_findings 可合并并去重。"""
    b = Baseline()
    results = {
        "a.py": [{"type": "R1", "file": "a.py", "line": 1}],
        "b.js": [{"type": "R2", "file": "b.js", "line": 2}],
    }
    b.add_findings(results, tmp_path)
    assert len(b._by_fingerprint) >= 2


def test_filter_suppressed_no_comment() -> None:
    """无 aegis-ignore 时不过滤。"""
    findings = [{"type": "SQL_INJECTION", "line": 1}]
    source = "cursor.execute(query)"
    assert len(filter_suppressed_findings(findings, source)) == 1


def test_filter_suppressed_line_comment() -> None:
    """行内 aegis-ignore 抑制该行所有。"""
    findings = [{"type": "SQL_INJECTION", "line": 2}]
    source = "x = 1\ncursor.execute(query)  // aegis-ignore\nz = 2"
    assert len(filter_suppressed_findings(findings, source)) == 0


def test_filter_suppressed_rule_specific() -> None:
    """aegis-ignore: RULE_ID 仅抑制该规则。"""
    findings = [
        {"type": "SQL_INJECTION", "line": 2},
        {"type": "XSS_RISK", "line": 2},
    ]
    source = "line1\nbad_code()  # aegis-ignore: SQL_INJECTION\nline3"
    out = filter_suppressed_findings(findings, source)
    assert len(out) == 1
    assert out[0]["type"] == "XSS_RISK"


def test_filter_suppressed_wrong_line_not_suppressed() -> None:
    """aegis-ignore 仅抑制注释所在行；其他行不抑制。"""
    findings = [{"type": "SQL_INJECTION", "line": 1}]
    source = "cursor.execute(q)  # aegis-ignore\nsafe()"
    out = filter_suppressed_findings(findings, source)
    assert len(out) == 0
    findings2 = [{"type": "SQL_INJECTION", "line": 2}]
    out2 = filter_suppressed_findings(findings2, source)
    assert len(out2) == 1


def test_filter_suppressed_empty_source_unchanged() -> None:
    """空源码或空 findings 时原样返回。"""
    assert filter_suppressed_findings([], "any") == []
    assert filter_suppressed_findings([{"type": "X", "line": 1}], "") == [{"type": "X", "line": 1}]
