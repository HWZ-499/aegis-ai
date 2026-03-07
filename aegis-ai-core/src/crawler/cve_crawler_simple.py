# cve_crawler_simple.py - 简化版 CVE 爬虫（支持多种数据源和测试模式）
"""
简化版 CVE 数据爬虫：
1. 支持测试模式（使用模拟数据）
2. 支持从文件导入
3. 支持手动添加数据
4. 为未来接入真实 API 预留接口
"""

import json
import logging
import os
from datetime import datetime

# 环境变量处理
keys_to_remove = ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"]
for key in keys_to_remove:
    if key in os.environ:
        os.environ.pop(key)

import chromadb

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("cve_crawler.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

LAST_UPDATE_FILE = "last_update.txt"


class SimpleCVECrawler:
    """简化版 CVE 爬虫（支持测试和手动模式）"""

    def __init__(self, db_path: str = "./aegis_db", collection_name: str = "cve_core"):
        """初始化爬虫"""
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)
        logger.info(f"✅ 连接数据库成功，当前有 {self.collection.count()} 条记录")

    def get_sample_cves(self) -> list[dict]:
        """
        获取示例 CVE 数据（用于测试）

        Returns:
            示例 CVE 数据列表
        """
        return [
            {
                "id": "CVE-2021-44228",
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "severity": "Critical",
                "cvss_score": 10.0,
                "published": "2021-12-10T00:00:00.000Z",
                "cwe_ids": ["CWE-502"],
            },
            {
                "id": "CVE-2021-45046",
                "description": "Apache Log4j2 versions 2.15.0, 2.16.0, and 2.17.0 are vulnerable to remote code execution (RCE) attacks when the configuration uses a non-default Pattern Layout with a Context Lookup.",
                "severity": "Critical",
                "cvss_score": 9.0,
                "published": "2021-12-14T00:00:00.000Z",
                "cwe_ids": ["CWE-502"],
            },
            {
                "id": "CVE-2021-26295",
                "description": "Fastjson 1.2.80 and below are vulnerable to remote code execution (RCE) attacks via the @type attribute in JSON data.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2021-03-15T00:00:00.000Z",
                "cwe_ids": ["CWE-502"],
            },
            {
                "id": "CVE-2022-21413",
                "description": "Oracle Java SE and Oracle GraalVM Enterprise Edition are vulnerable to signature verification bypass, allowing attackers to forge signatures.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2022-04-19T00:00:00.000Z",
                "cwe_ids": ["CWE-347"],
            },
            {
                "id": "CVE-2023-34362",
                "description": "MOVEit Transfer SQL injection vulnerability allows remote code execution.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "published": "2023-06-01T00:00:00.000Z",
                "cwe_ids": ["CWE-89"],
            },
            {
                "id": "CVE-2023-50505",
                "description": "Fastjson remote code execution vulnerability in parse function due to deserialization flaw.",
                "severity": "High",
                "cvss_score": 8.8,
                "published": "2023-12-01T00:00:00.000Z",
                "cwe_ids": ["CWE-502"],
            },
            {
                "id": "CVE-2020-11974",
                "description": "Apache Airflow command injection vulnerability allows remote code execution.",
                "severity": "High",
                "cvss_score": 8.8,
                "published": "2020-05-11T00:00:00.000Z",
                "cwe_ids": ["CWE-78"],
            },
        ]

    def format_document(self, cve_data: dict) -> str:
        """格式化 CVE 数据为文档字符串"""
        parts = [
            f"漏洞编号: {cve_data['id']}",
            f"摘要: {cve_data['description'][:200]}",
            f"严重程度: {cve_data['severity']}",
            f"CVSS 分数: {cve_data['cvss_score']}",
        ]

        if cve_data.get("cwe_ids"):
            parts.append(f"CWE: {', '.join(cve_data['cwe_ids'])}")

        return "; ".join(parts)

    def load_from_file(self, file_path: str) -> list[dict]:
        """
        从 JSON 文件加载 CVE 数据

        Args:
            file_path: JSON 文件路径

        Returns:
            CVE 数据列表
        """
        try:
            with open(file_path, encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict) and "cves" in data:
                    return data["cves"]
                else:
                    logger.error("❌ JSON 文件格式错误")
                    return []
        except FileNotFoundError:
            logger.error(f"❌ 文件不存在: {file_path}")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"❌ JSON 解析错误: {e}")
            return []

    def update_database(self, cve_list: list[dict], incremental: bool = True):
        """
        更新数据库

        Args:
            cve_list: CVE 数据列表
            incremental: 是否增量更新
        """
        if not cve_list:
            logger.warning("⚠️ 没有数据需要更新")
            return

        # 获取现有 ID
        existing_ids = set()
        if incremental:
            try:
                existing_data = self.collection.get()
                existing_ids = set(existing_data.get("ids", []))
            except Exception as e:
                logger.debug("获取现有 CVE ID 失败，将全量更新: %s", e)

        # 准备数据
        ids = []
        documents = []
        metadatas = []

        new_count = 0
        skip_count = 0

        for cve_data in cve_list:
            cve_id = cve_data["id"]

            # 增量更新：跳过已存在的
            if incremental and cve_id in existing_ids:
                skip_count += 1
                continue

            ids.append(cve_id)
            documents.append(self.format_document(cve_data))
            metadatas.append(
                {
                    "severity": cve_data.get("severity", "Unknown"),
                    "cvss_score": str(cve_data.get("cvss_score", 0.0)),
                    "published": cve_data.get("published", ""),
                    "cwe_ids": ",".join(cve_data.get("cwe_ids", [])),
                    "source": "manual",
                    "crawled_at": datetime.now().isoformat(),
                }
            )
            new_count += 1

        if not ids:
            logger.info(f"ℹ️ 没有新数据需要添加（跳过 {skip_count} 条已存在的数据）")
            return

        # 写入数据库
        logger.info(f"💾 正在写入数据库：{new_count} 条新增，{skip_count} 条跳过...")
        self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        logger.info(f"✅ 数据库更新完成！当前共有 {self.collection.count()} 条记录")

    def save_update_time(self):
        """保存更新时间"""
        with open(LAST_UPDATE_FILE, "w") as f:
            f.write(str(datetime.now().timestamp()))
        logger.info(f"💾 已保存更新时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def run_test_mode(self, count: int = 10):
        """
        测试模式：使用示例数据

        Args:
            count: 使用多少条示例数据
        """
        logger.info("=" * 70)
        logger.info("🧪 测试模式：使用示例 CVE 数据")
        logger.info("=" * 70)

        sample_cves = self.get_sample_cves()[:count]
        self.update_database(sample_cves, incremental=True)
        self.save_update_time()

        logger.info("=" * 70)

    def run_from_file(self, file_path: str):
        """
        从文件导入模式

        Args:
            file_path: JSON 文件路径
        """
        logger.info("=" * 70)
        logger.info(f"📁 从文件导入：{file_path}")
        logger.info("=" * 70)

        cve_list = self.load_from_file(file_path)
        if cve_list:
            self.update_database(cve_list, incremental=True)
            self.save_update_time()
        else:
            logger.error("❌ 没有数据可导入")

        logger.info("=" * 70)


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="简化版 CVE 数据爬虫（支持测试和文件导入）")
    parser.add_argument("--test", action="store_true", help="测试模式（使用示例数据）")
    parser.add_argument("--test-count", type=int, default=10, help="测试模式使用的数据量（默认：10）")
    parser.add_argument("--file", type=str, help="从 JSON 文件导入")
    parser.add_argument("--full", action="store_true", help="全量更新（不增量）")

    args = parser.parse_args()

    crawler = SimpleCVECrawler()

    if args.test:
        crawler.run_test_mode(count=args.test_count)
    elif args.file:
        crawler.run_from_file(args.file)
    else:
        # 默认：测试模式
        logger.info("ℹ️ 未指定模式，使用测试模式（示例数据）")
        logger.info("   提示: 使用 --test 显式指定测试模式")
        logger.info("   提示: 使用 --file <path> 从文件导入")
        crawler.run_test_mode(count=args.test_count)


if __name__ == "__main__":
    main()
