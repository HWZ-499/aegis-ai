import json
from pathlib import Path

import pytest

from src.analysis.taint.cross_file_analyzer import CrossFileAnalyzer
from src.lsp.server import WorkspaceContext
from src.scanner.cli import main
from src.scanner.project_scanner import ProjectScanner


def _write_project(root: Path, files: dict[str, str]) -> None:
    for relative_path, source in files.items():
        file_path = root / relative_path
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_path.write_text(source, encoding="utf-8")


def test_python_cross_file_parameter_to_ssrf_sink(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "helper.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "unsafe.py": ('from helper import fetch\nurl = request.args.get("url")\nfetch(url)\n'),
            "safe.py": ('from helper import fetch\nurl = "https://example.com/health"\nfetch(url)\n'),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SSRF_PY_TAINT"
    assert finding["file"] == "helper.py"
    assert finding["line"] == 3
    assert finding["cross_file"] is True
    assert Path(finding["caller_file"]).name == "unsafe.py"
    assert finding["related_locations"][0]["start_line"] == 2
    assert analyzer.get_stats()["function_contracts"] == 1


def test_javascript_esmodule_and_commonjs_cross_file_propagation(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "helper.js": ('import axios from "axios";\nexport function fetchUrl(url) {\n  return axios.get(url);\n}\n'),
            "esm.js": ('import { fetchUrl } from "./helper.js";\nconst url = req.query.url;\nfetchUrl(url);\n'),
            "commonjs.js": ('const { fetchUrl: loadUrl } = require("./helper.js");\nloadUrl(req.body.url);\n'),
            "safe.js": ('import { fetchUrl } from "./helper.js";\nfetchUrl("https://example.com/health");\n'),
            "default-helper.cjs": (
                'const axios = require("axios");\nmodule.exports = function (url) {\n  return axios.get(url);\n};\n'
            ),
            "default-caller.cjs": ('const fetchUrl = require("./default-helper.cjs");\nfetchUrl(req.query.url);\n'),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 3
    assert {finding["rule_id"] for finding in findings} == {"SSRF_JS_TAINT"}
    assert {Path(finding["caller_file"]).name for finding in findings} == {
        "esm.js",
        "commonjs.js",
        "default-caller.cjs",
    }
    assert {finding["file"] for finding in findings} == {"helper.js", "default-helper.cjs"}
    assert analyzer.get_stats()["dependency_edges"] == 4


def test_project_scanner_cross_file_analysis_is_explicit_and_reports_stats(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "helper.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "app.py": ('from helper import fetch\nfetch(request.args.get("url"))\n'),
        },
    )

    default_results = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
    ).scan_project()
    assert default_results == {}

    scanner = ProjectScanner(
        str(tmp_path),
        use_cache=False,
        use_parallel=False,
        use_cross_file=True,
    )
    results = scanner.scan_project()
    stats = scanner.get_stats()

    assert len(results["helper.py"]) == 1
    assert results["helper.py"][0]["source"] == "CrossFile"
    assert stats["total_issues"] == 1
    assert stats["files_with_issues"] == 1
    assert stats["cross_file_analysis"]["cross_file_findings"] == 1


def test_lsp_workspace_context_reuses_cross_file_analyzer_findings(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "helper.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "app.py": ("from helper import fetch\nfetch(request.args.get('url'))\n"),
        },
    )
    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    context = WorkspaceContext()
    context.configure({"experimental_cross_file": True})
    context._analyzer = analyzer

    helper_findings = context.get_cross_file_findings(str(tmp_path / "helper.py"))
    app_findings = context.get_cross_file_findings(str(tmp_path / "app.py"))

    assert len(helper_findings) == 1
    assert helper_findings[0]["rule_id"] == "SSRF_PY_TAINT"
    assert app_findings == []


def test_cli_cross_file_flag_uses_project_scanner_findings(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    _write_project(
        project,
        {
            "helper.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "app.py": ("from helper import fetch\nfetch(request.args.get('url'))\n"),
        },
    )
    output = tmp_path / "cross-file.json"

    with pytest.raises(SystemExit) as exit_info:
        main(
            [
                str(project),
                "--cross-file",
                "--format",
                "json",
                "--output",
                str(output),
                "--no-cache",
                "--no-parallel",
                "--no-fail-on-findings",
            ]
        )

    assert exit_info.value.code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    finding = report["results"]["helper.py"][0]
    assert finding["rule_id"] == "SSRF_PY_TAINT"
    assert finding["cross_file"] is True
    assert report["summary"]["total_issues"] == 1


def test_python_multihop_and_reexport_propagate_to_original_sink(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "sink.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "service.py": ("from sink import fetch\ndef load(url):\n    return fetch(url)\n"),
            "facade.py": "from service import load as forwarded\n",
            "app.py": ('from facade import forwarded\nurl = request.args.get("url")\nforwarded(url)\n'),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SSRF_PY_TAINT"
    assert finding["file"] == "sink.py"
    assert Path(finding["caller_file"]).name == "app.py"
    assert finding["caller_line"] == 3
    assert analyzer.get_stats()["function_contracts"] == 2


def test_javascript_multihop_and_reexport_propagate_to_original_sink(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "sink.js": ('import axios from "axios";\nexport function fetchUrl(url) {\n  return axios.get(url);\n}\n'),
            "service.js": (
                'import { fetchUrl } from "./sink.js";\nexport function load(url) {\n  return fetchUrl(url);\n}\n'
            ),
            "facade.js": 'export { load as forwarded } from "./service.js";\n',
            "app.js": ('import { forwarded } from "./facade.js";\nconst url = req.query.url;\nforwarded(url);\n'),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SSRF_JS_TAINT"
    assert finding["file"] == "sink.js"
    assert Path(finding["caller_file"]).name == "app.js"
    assert finding["caller_line"] == 3
    assert analyzer.get_stats()["function_contracts"] == 2


def test_commonjs_property_reexport_resolves_original_contract(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "sink.cjs": (
                'const axios = require("axios");\nexports.fetchUrl = function (url) {\n  return axios.get(url);\n};\n'
            ),
            "facade.cjs": ('const sink = require("./sink.cjs");\nmodule.exports.forwarded = sink.fetchUrl;\n'),
            "app.cjs": ('const { forwarded } = require("./facade.cjs");\nforwarded(req.query.url);\n'),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SSRF_JS_TAINT"
    assert findings[0]["file"] == "sink.cjs"
    assert Path(findings[0]["caller_file"]).name == "app.cjs"


def test_python_imported_return_value_marks_assignment_tainted(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "source.py": (
                "def current_url():\n"
                '    return request.args.get("url")\n'
                "\n"
                "def health_url():\n"
                '    return "https://example.com/health"\n'
            ),
            "sink.py": ("import requests\ndef fetch(url):\n    return requests.get(url)\n"),
            "unsafe.py": ("from source import current_url\nfrom sink import fetch\nurl = current_url()\nfetch(url)\n"),
            "safe.py": ("from source import health_url\nfrom sink import fetch\nurl = health_url()\nfetch(url)\n"),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SSRF_PY_TAINT"
    assert Path(finding["caller_file"]).name == "unsafe.py"
    assert finding["related_locations"][-1]["start_line"] == 3


def test_javascript_multihop_return_value_marks_assignment_tainted(tmp_path: Path) -> None:
    _write_project(
        tmp_path,
        {
            "source.js": "export const currentUrl = () => req.query.url;\n",
            "source-facade.js": (
                'import { currentUrl } from "./source.js";\nexport function loadUrl() {\n  return currentUrl();\n}\n'
            ),
            "sink.js": ('import axios from "axios";\nexport function fetchUrl(url) {\n  return axios.get(url);\n}\n'),
            "app.js": (
                'import { loadUrl } from "./source-facade.js";\n'
                'import { fetchUrl } from "./sink.js";\n'
                "const url = loadUrl();\n"
                "fetchUrl(url);\n"
            ),
        },
    )

    analyzer = CrossFileAnalyzer(tmp_path)
    analyzer.scan_project()

    findings = analyzer.get_findings()
    assert len(findings) == 1
    finding = findings[0]
    assert finding["rule_id"] == "SSRF_JS_TAINT"
    assert Path(finding["caller_file"]).name == "app.js"
    assert finding["related_locations"][-1]["start_line"] == 3
