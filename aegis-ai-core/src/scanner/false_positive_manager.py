# false_positive_manager.py - 误报管理
"""
误报管理功能：标记误报，忽略特定问题。

支持两种误报标记方式：
1. JSON 配置文件（.aegis-fp.json）：通过 FalsePositiveManager 管理
2. 内联注释（行内或行上方）：通过 InlineSuppressor 解析源代码中的注释

内联注释格式：
  # aegis-ignore               ← 忽略该行所有漏洞
  # aegis-ignore: VULN_TYPE    ← 仅忽略该行的指定漏洞类型
  // aegis-ignore              ← JavaScript/TypeScript/PHP/Java/Go 等（同上）
  // aegis-ignore: SQL_INJECTION

注释可放在漏洞行末尾，或漏洞行的上一行。
"""

import json
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class FalsePositiveManager:
    """
    误报管理器

    支持标记误报，忽略特定问题
    """

    def __init__(self, config_path: str | None = None):
        """
        初始化误报管理器

        Args:
            config_path: 配置文件路径（JSON 格式），如果为 None，使用默认路径
        """
        if config_path:
            self.config_path = Path(config_path)
        else:
            # 默认配置文件路径：项目根目录下的 .aegis-fp.json
            self.config_path = Path.cwd() / ".aegis-fp.json"

        self.false_positives = self._load_config()

    @staticmethod
    def _normalize_fp_entries(entries: object) -> list[dict[str, Any]]:
        if not isinstance(entries, list):
            return []
        normalized: list[dict[str, Any]] = []
        for item in entries:
            if isinstance(item, dict):
                normalized.append(item)
        return normalized

    def _load_config(self) -> dict[str, Any]:
        """
        加载误报配置

        Returns:
            误报配置字典
        """
        default_config: dict[str, Any] = {"version": "1.0", "false_positives": []}

        if self.config_path.exists():
            try:
                with open(self.config_path, encoding="utf-8") as f:
                    config = json.load(f)

                if not isinstance(config, dict):
                    logger.warning("误报配置格式无效（顶层不是对象），使用默认配置")
                    return default_config

                version = config.get("version")
                if not isinstance(version, str):
                    version = default_config["version"]
                false_positives = self._normalize_fp_entries(config.get("false_positives"))

                return {"version": version, "false_positives": false_positives}
            except (OSError, json.JSONDecodeError) as e:
                logger.warning("加载误报配置文件失败: %s，使用默认配置", e)
                return default_config

        return default_config

    def _save_config(self):
        """保存配置到文件"""
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.config_path, "w", encoding="utf-8") as f:
            json.dump(self.false_positives, f, indent=2, ensure_ascii=False)

    def is_false_positive(self, file_path: str, line: int, vuln_type: str, details: str = "") -> bool:
        """
        检查是否是误报

        Args:
            file_path: 文件路径
            line: 行号
            vuln_type: 漏洞类型
            details: 问题详情（可选）

        Returns:
            是否是误报
        """
        fp_list = self.false_positives.get("false_positives", [])

        for fp in fp_list:
            # 匹配文件路径
            if fp.get("file_path") != file_path:
                continue

            # 匹配行号
            if fp.get("line") != line:
                continue

            # 匹配漏洞类型
            if fp.get("type") != vuln_type:
                continue

            # 如果提供了 details，也匹配 details
            if details and fp.get("details"):
                if details not in fp.get("details", ""):
                    continue

            return True

        return False

    def add_false_positive(self, file_path: str, line: int, vuln_type: str, details: str = "", reason: str = ""):
        """
        添加误报标记

        Args:
            file_path: 文件路径
            line: 行号
            vuln_type: 漏洞类型
            details: 问题详情（可选）
            reason: 标记为误报的原因（可选）
        """
        fp_list = self.false_positives.get("false_positives", [])

        # 检查是否已存在
        for fp in fp_list:
            if fp.get("file_path") == file_path and fp.get("line") == line and fp.get("type") == vuln_type:
                logger.info("该问题已被标记为误报")
                return

        # 添加新的误报标记
        fp_entry = {
            "file_path": file_path,
            "line": line,
            "type": vuln_type,
            "details": details,
            "reason": reason,
            "created_at": datetime.now().isoformat(),
        }

        fp_list.append(fp_entry)
        self.false_positives["false_positives"] = fp_list
        self._save_config()

        logger.info("已标记为误报: %s:%s - %s", file_path, line, vuln_type)

    def remove_false_positive(self, file_path: str, line: int, vuln_type: str):
        """
        移除误报标记

        Args:
            file_path: 文件路径
            line: 行号
            vuln_type: 漏洞类型
        """
        fp_list = self.false_positives.get("false_positives", [])

        original_count = len(fp_list)
        fp_list[:] = [
            fp
            for fp in fp_list
            if not (fp.get("file_path") == file_path and fp.get("line") == line and fp.get("type") == vuln_type)
        ]

        if len(fp_list) < original_count:
            self.false_positives["false_positives"] = fp_list
            self._save_config()
            logger.info("已移除误报标记: %s:%s - %s", file_path, line, vuln_type)
        else:
            logger.info("未找到匹配的误报标记")

    def filter_findings(self, findings: list[dict], file_path: str = "") -> list[dict]:
        """
        过滤误报

        Args:
            findings: 检测结果列表
            file_path: 文件路径（用于匹配）

        Returns:
            过滤后的检测结果列表
        """
        filtered = []

        for finding in findings:
            fp_file_path = finding.get("file_path", file_path)
            line = finding.get("line", 0)
            vuln_type = finding.get("type", "")
            details = finding.get("details", "")

            if not self.is_false_positive(fp_file_path, line, vuln_type, details):
                filtered.append(finding)

        return filtered

    def list_false_positives(self) -> list[dict[str, Any]]:
        """
        列出所有误报标记

        Returns:
            误报标记列表
        """
        return self._normalize_fp_entries(self.false_positives.get("false_positives"))


class InlineSuppressor:
    """
    内联注释误报抑制器。

    解析源代码中的 ``# aegis-ignore`` / ``// aegis-ignore`` 注释，
    在漏洞所在行或上一行查找抑制指令，从而过滤相应 findings。

    支持格式：
        # aegis-ignore                  ← 抑制该行所有漏洞
        # aegis-ignore: SQL_INJECTION   ← 仅抑制该行的 SQL_INJECTION
        // aegis-ignore                 ← JS/TS/PHP/Java/Go 等
        // aegis-ignore: XSS_RISK

    用法示例：
        suppressor = InlineSuppressor(source_code)
        findings = suppressor.filter_findings(findings)
    """

    # 匹配 "# aegis-ignore" 或 "// aegis-ignore"，可选 ": VULN_TYPE"
    _PATTERN = re.compile(
        r"(?:#|//)\s*aegis-ignore(?:\s*:\s*([A-Z_]+))?",
        re.IGNORECASE,
    )

    def __init__(self, source_code: str) -> None:
        """
        初始化内联抑制器。

        Args:
            source_code: 完整源代码字符串（用于解析行内注释）
        """
        self._lines = source_code.splitlines() if source_code else []
        # 预构建行号→抑制类型集合的映射（1-indexed）
        # None 表示抑制所有类型
        self._suppressed: dict[int, set[str] | None] = {}
        self._build_index()

    def _build_index(self) -> None:
        """扫描所有代码行，构建抑制索引。

        规则：
        - 行内注释（注释前有代码）：仅抑制当前行
        - 独立注释行（仅含注释，可有前导空白）：抑制下一行
        """
        for i, line in enumerate(self._lines, start=1):
            comment = self._extract_line_comment(line)
            if comment is None:
                continue

            comment_start, comment_text = comment
            m = self._PATTERN.search(comment_text)
            if m is None:
                continue
            vuln_type = m.group(1)
            if vuln_type:
                vuln_type = vuln_type.upper().strip()

            # 判断是独立注释行还是行内注释
            # 独立注释行：注释标记前仅有空白字符
            before_comment = line[:comment_start]
            is_standalone = before_comment.strip() == ""

            target_lines = (i + 1,) if is_standalone else (i,)

            for target_line in target_lines:
                if target_line in self._suppressed and self._suppressed[target_line] is None:
                    # 已被通配符抑制，不做修改
                    continue
                if vuln_type is None:
                    # 通配符：抑制所有类型
                    self._suppressed[target_line] = None
                else:
                    if target_line not in self._suppressed:
                        self._suppressed[target_line] = set()
                    if self._suppressed[target_line] is not None:
                        self._suppressed[target_line].add(vuln_type)  # type: ignore[union-attr]

    @staticmethod
    def _extract_line_comment(line: str) -> tuple[int, str] | None:
        """Return the first line-comment segment outside simple string literals."""
        quote: str | None = None
        escaped = False
        i = 0
        while i < len(line):
            char = line[i]

            if quote is not None:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                i += 1
                continue

            if char in {"'", '"', "`"}:
                quote = char
                i += 1
                continue

            if char == "#":
                return i, line[i:]
            if char == "/" and i + 1 < len(line) and line[i + 1] == "/":
                return i, line[i:]

            i += 1

        return None

    def is_suppressed(self, line: int, vuln_type: str) -> bool:
        """
        判断指定行的指定漏洞类型是否被内联注释抑制。

        Args:
            line: 漏洞行号（1-indexed）
            vuln_type: 漏洞类型字符串（如 "SQL_INJECTION"）

        Returns:
            True 表示应被抑制（视为误报）
        """
        suppressed = self._suppressed.get(line)
        if line not in self._suppressed:
            return False
        if suppressed is None:
            # 通配符：抑制所有类型
            return True
        return vuln_type.upper() in suppressed

    def filter_findings(self, findings: list[dict]) -> list[dict]:
        """
        过滤被内联注释抑制的 findings。

        Args:
            findings: 检测结果列表（每项含 "line" 和 "type" 字段）

        Returns:
            过滤后的检测结果列表
        """
        result = []
        for finding in findings:
            line = finding.get("line", 0) or 0
            vuln_type = finding.get("type", "")
            if not self.is_suppressed(line, vuln_type):
                result.append(finding)
            else:
                logger.debug(
                    "内联抑制: 行 %d [%s] 被 aegis-ignore 注释过滤",
                    line,
                    vuln_type,
                )
        return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="误报管理工具")
    parser.add_argument("--config", help="配置文件路径")
    parser.add_argument("--add", nargs=4, metavar=("FILE", "LINE", "TYPE", "REASON"), help="添加误报标记")
    parser.add_argument("--remove", nargs=3, metavar=("FILE", "LINE", "TYPE"), help="移除误报标记")
    parser.add_argument("--list", action="store_true", help="列出所有误报标记")

    args = parser.parse_args()

    manager = FalsePositiveManager(args.config)

    if args.add:
        file_path, line, vuln_type, reason = args.add
        manager.add_false_positive(file_path, int(line), vuln_type, reason=reason)

    if args.remove:
        file_path, line, vuln_type = args.remove
        manager.remove_false_positive(file_path, int(line), vuln_type)

    if args.list:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
        fp_list = manager.list_false_positives()
        if fp_list:
            logger.info("误报标记列表:")
            for fp in fp_list:
                logger.info("  文件: %s", fp.get("file_path"))
                logger.info("  行号: %s", fp.get("line"))
                logger.info("  类型: %s", fp.get("type"))
                if fp.get("reason"):
                    logger.info("  原因: %s", fp.get("reason"))
        else:
            logger.info("没有误报标记")
