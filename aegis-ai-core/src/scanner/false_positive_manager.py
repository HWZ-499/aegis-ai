# false_positive_manager.py - 误报管理
"""
误报管理功能：标记误报，忽略特定问题
"""

import json
import logging
from pathlib import Path

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

    def _load_config(self) -> dict:
        """
        加载误报配置

        Returns:
            误报配置字典
        """
        default_config = {"version": "1.0", "false_positives": []}

        if self.config_path.exists():
            try:
                with open(self.config_path, encoding="utf-8") as f:
                    config = json.load(f)
                    return config
            except Exception as e:
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
            "created_at": str(Path.cwd()),  # 可以改为时间戳
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

    def list_false_positives(self) -> list[dict]:
        """
        列出所有误报标记

        Returns:
            误报标记列表
        """
        return self.false_positives.get("false_positives", [])


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
