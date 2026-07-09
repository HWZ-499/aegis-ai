"""Regression coverage for the maintained C/C++ partial-support path."""

from __future__ import annotations

import inspect

import pytest

from src.analysis.rule_engine import analyze_c_cpp, analyze_source


@pytest.mark.parametrize(
    ("source", "expected_type"),
    [
        ("char b[8];\nstrcpy(b, input);", "BUFFER_OVERFLOW"),
        ("printf(user_input);", "FORMAT_STRING"),
        ("system(user_cmd);", "RCE_COMMAND_EXEC"),
        ('fopen(base + user_path, "r");', "PATH_TRAVERSAL"),
        ("void *p = malloc(64);", "MEMORY_LEAK"),
        ("free(p);", "USE_AFTER_FREE"),
        ("char name[20];\ncin >> name;", "BUFFER_OVERFLOW"),
        ("TerminateThread(handle, 0);", "THREAD_LIFECYCLE_RISK"),
    ],
)
def test_c_cpp_detection_matrix_is_preserved(source: str, expected_type: str) -> None:
    findings = analyze_c_cpp(source, "sample.cpp")

    assert any(finding.get("type") == expected_type for finding in findings)


def test_c_cpp_comments_and_strings_do_not_create_findings() -> None:
    source = """
// system(user_cmd);
const char *example = "strcpy(buffer, input)";
/* printf(user_input); */
"""

    assert analyze_c_cpp(source, "sample.cpp") == []


@pytest.mark.parametrize("file_path", ["sample.c", "sample.cpp", "sample.hpp"])
def test_c_cpp_canonical_dispatch_uses_maintained_rules(file_path: str) -> None:
    findings = analyze_source("system(user_cmd);", file_path)

    assert any(finding.get("type") == "RCE_COMMAND_EXEC" for finding in findings)


def test_c_cpp_production_entry_has_no_legacy_dispatch() -> None:
    source = inspect.getsource(analyze_c_cpp)

    assert "multi_language_ast" not in source
    assert "scan_code_locally" not in source
    assert "security_rules" not in source
