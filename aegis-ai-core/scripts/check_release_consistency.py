from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _extract_python_requirement(pyproject_text: str) -> str | None:
    match = re.search(r"requires-python\s*=\s*[\"']([^\"']+)[\"']", pyproject_text)
    return match.group(1) if match else None


def _extract_provider_enum(package_json_text: str) -> list[str]:
    payload = json.loads(package_json_text)
    props = payload.get("contributes", {}).get("configuration", {}).get("properties", {})
    provider = props.get("aegisAI.ai.provider", {})
    enum = provider.get("enum", [])
    return [str(item) for item in enum]


def _extract_project_urls(pyproject_text: str) -> dict[str, str]:
    payload = tomllib.loads(pyproject_text)
    urls = payload.get("project", {}).get("urls", {})
    return {str(key): str(value) for key, value in urls.items()}


def _extract_extension_metadata(package_json_text: str) -> dict[str, str]:
    payload = json.loads(package_json_text)
    repository = payload.get("repository", {})
    bugs = payload.get("bugs", {})
    return {
        "repository": str(repository.get("url", "")),
        "bugs": str(bugs.get("url", "")),
        "homepage": str(payload.get("homepage", "")),
        "version": str(payload.get("version", "")),
    }


def _normalize_repo_url(url: str) -> str:
    cleaned = url.strip().rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    if cleaned.endswith("#readme"):
        cleaned = cleaned[:-7]
    if cleaned.endswith("/issues"):
        cleaned = cleaned[:-7]
    return cleaned


def _extract_src_directory_refs(src_readme_text: str) -> list[str]:
    refs: list[str] = []
    for line in src_readme_text.splitlines():
        match = re.search(r"`([^`]+/)`", line)
        if match:
            refs.append(match.group(1))
    return refs


def _looks_like_repo_root(path: Path) -> bool:
    return (
        (path / "README.md").is_file()
        and (path / "aegis-ai-core" / "pyproject.toml").is_file()
        and (path / "aegis-vscode" / "package.json").is_file()
        and (path / "docs" / "technical" / "TECHNICAL_DESIGN_DOCUMENT.md").is_file()
    )


def _resolve_repo_root(repo_root: Path) -> Path:
    for candidate in (repo_root, *repo_root.parents):
        if _looks_like_repo_root(candidate):
            return candidate
    raise FileNotFoundError(
        f"Could not locate Aegis monorepo root from {repo_root}. Expected README.md, aegis-ai-core/, aegis-vscode/, and docs/."
    )


def validate_repo_consistency(repo_root: Path) -> list[str]:
    """Validate high-signal product/docs consistency for release gating."""
    errors: list[str] = []
    repo_root = _resolve_repo_root(repo_root)

    root_readme = _read_text(repo_root / "README.md")
    extension_readme = _read_text(repo_root / "aegis-vscode" / "README.md")
    tech_doc = _read_text(repo_root / "docs" / "technical" / "TECHNICAL_DESIGN_DOCUMENT.md")
    pyproject = _read_text(repo_root / "aegis-ai-core" / "pyproject.toml")
    package_json = _read_text(repo_root / "aegis-vscode" / "package.json")
    src_readme = _read_text(repo_root / "aegis-ai-core" / "src" / "README.md")

    python_requirement = _extract_python_requirement(pyproject)
    if python_requirement and python_requirement not in root_readme:
        errors.append(f"Root README must document Python requirement {python_requirement}.")

    install_markers = ("pip install -e .[dev]", "pip install -e .")
    if not any(marker in root_readme for marker in install_markers):
        errors.append("Root README must document the editable install command.")

    provider_enum = _extract_provider_enum(package_json)
    for provider in provider_enum:
        if provider not in extension_readme and provider not in root_readme:
            errors.append(f"AI provider '{provider}' must be documented in README content.")

    for key_name in ("DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
        if key_name not in root_readme or key_name not in extension_readme:
            errors.append(f"AI provider key {key_name} must be documented in both READMEs.")

    if "OLLAMA_BASE_URL" not in root_readme or "OLLAMA_BASE_URL" not in extension_readme:
        errors.append("AI provider key OLLAMA_BASE_URL must be documented in both READMEs.")

    capability_markers = ("已支持", "实验性", "规划中")
    if not all(marker in root_readme for marker in capability_markers):
        errors.append("Root README must expose the supported/experimental/planned capability matrix.")
    if not all(marker in tech_doc for marker in capability_markers):
        errors.append("Technical design document must expose the supported/experimental/planned capability matrix.")

    if ".aegis-baseline.json" not in root_readme or "不是修复代码" not in root_readme:
        errors.append("Root README must explain that baseline suppresses findings and is not a fix.")

    project_urls = _extract_project_urls(pyproject)
    extension_metadata = _extract_extension_metadata(package_json)
    repo_candidates = {
        _normalize_repo_url(project_urls.get("Homepage", "")),
        _normalize_repo_url(project_urls.get("Repository", "")),
        _normalize_repo_url(project_urls.get("Issues", "")),
        _normalize_repo_url(extension_metadata["repository"]),
        _normalize_repo_url(extension_metadata["bugs"]),
        _normalize_repo_url(extension_metadata["homepage"]),
    }
    repo_candidates.discard("")
    if len(repo_candidates) > 1:
        errors.append("Repository metadata must point to a single GitHub repository across pyproject.toml and package.json.")

    if extension_metadata["version"] and extension_metadata["version"] not in extension_readme:
        errors.append(f"Extension README must mention the packaged extension version {extension_metadata['version']}.")

    src_root = repo_root / "aegis-ai-core" / "src"
    for directory_ref in _extract_src_directory_refs(src_readme):
        if not (src_root / directory_ref.rstrip("/")).is_dir():
            errors.append(f"src/README.md references missing directory '{directory_ref}'.")

    return errors


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    errors = validate_repo_consistency(repo_root)
    if errors:
        for error in errors:
            print(f"[consistency] {error}")
        return 1
    print("[consistency] OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
