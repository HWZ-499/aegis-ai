# cve_crawler_auto.py - 自动化 CVE 数据爬虫（支持定时任务）
"""
自动化 CVE 数据爬虫：
1. 从 NVD API 获取最新的 CVE 数据
2. 支持定时任务（每天/每周自动更新）
3. 增量更新（只获取新数据，避免重复）
4. 数据清洗与向量化
"""

import logging
import os
import time
from datetime import datetime, timedelta

# 环境变量处理
keys_to_remove = ["REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"]
for key in keys_to_remove:
    if key in os.environ:
        os.environ.pop(key)

# 先加载环境变量（支持 .env 文件）
try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

import certifi
import chromadb
import httpx
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# SSL 证书配置
valid_cert_path = certifi.where()
os.environ["REQUESTS_CA_BUNDLE"] = valid_cert_path
os.environ["SSL_CERT_FILE"] = valid_cert_path

# 代理配置（如果需要）
PROXY_PORT = os.getenv("PROXY_PORT", "")
USE_PROXY = bool(PROXY_PORT)
PROXIES = None
if USE_PROXY:
    PROXIES = {"http": f"http://127.0.0.1:{PROXY_PORT}", "https": f"http://127.0.0.1:{PROXY_PORT}"}

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler("cve_crawler.log"), logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# 配置
# NVD API 2.0 需要 API Key
# 申请地址: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_BASE_V1 = "https://services.nvd.nist.gov/rest/json/cves/1.0"  # 1.0 版本，不需要 Key（已废弃）
NVD_API_BASE_V2 = "https://services.nvd.nist.gov/rest/json/cves/2.0"  # 2.0 版本，需要 Key（推荐）
# 注意：NVD_API_KEY 在函数内部动态读取，确保 .env 文件已加载

LAST_UPDATE_FILE = "last_update.txt"  # 记录上次更新时间
BATCH_SIZE = 20  # 每次请求的 CVE 数量
MAX_RESULTS = 100  # 每次运行最多获取的 CVE 数量


class CVECrawler:
    """CVE 数据爬虫类"""

    def __init__(self, db_path: str = "./aegis_db", collection_name: str = "cve_core"):
        """
        初始化爬虫

        Args:
            db_path: ChromaDB 数据库路径
            collection_name: 集合名称
        """
        self.client = chromadb.PersistentClient(path=db_path)
        self.collection = self.client.get_or_create_collection(name=collection_name)
        logger.info(f"✅ 连接数据库成功，当前有 {self.collection.count()} 条记录")

    def get_last_update_time(self) -> datetime | None:
        """
        获取上次更新时间

        Returns:
            上次更新的时间，如果不存在则返回 None
        """
        if os.path.exists(LAST_UPDATE_FILE):
            try:
                with open(LAST_UPDATE_FILE) as f:
                    timestamp = float(f.read().strip())
                    return datetime.fromtimestamp(timestamp)
            except Exception as e:
                logger.debug("读取上次更新时间失败: %s", e)
                return None
        return None

    def save_update_time(self, update_time: datetime):
        """
        保存更新时间

        Args:
            update_time: 更新时间
        """
        with open(LAST_UPDATE_FILE, "w") as f:
            f.write(str(update_time.timestamp()))
        logger.info(f"💾 已保存更新时间: {update_time.strftime('%Y-%m-%d %H:%M:%S')}")

    def fetch_cves_from_nvd(
        self,
        start_index: int = 0,
        results_per_page: int = 20,
        pub_start_date: str | None = None,
        pub_end_date: str | None = None,
        keyword: str | None = None,
    ) -> dict:
        """
        从 NVD API 获取 CVE 数据

        Args:
            start_index: 起始索引
            results_per_page: 每页结果数
            pub_start_date: 发布日期起始（格式：YYYY-MM-DDTHH:mm:ss.mmmZ）

        Returns:
            API 响应数据
        """
        # 动态检查 API Key（从环境变量重新读取）
        api_key = os.getenv("NVD_API_KEY", "")
        use_api_v2 = bool(api_key)

        # 选择 API 版本
        if use_api_v2:
            api_base = NVD_API_BASE_V2
            headers = {"apiKey": api_key}
            logger.info("ℹ️ 使用 NVD API 2.0（需要 Key）")
        else:
            api_base = NVD_API_BASE_V1
            headers = {}
            logger.info("ℹ️ 使用 NVD API 1.0（不需要 Key，但功能有限）")

        params = {"startIndex": start_index, "resultsPerPage": results_per_page}

        # API 2.0 需要同时提供 pubStartDate 和 pubEndDate
        # API 1.0 只需要 pubStartDate
        if pub_start_date:
            if use_api_v2:
                # API 2.0：需要开始和结束日期
                params["pubStartDate"] = pub_start_date
                if pub_end_date:
                    params["pubEndDate"] = pub_end_date
                else:
                    # 如果没有提供结束日期，使用当前时间
                    from datetime import datetime

                    params["pubEndDate"] = datetime.now().strftime("%Y-%m-%dT23:59:59.000Z")
            else:
                # API 1.0 格式：YYYY-MM-DD
                date_str = pub_start_date.split("T")[0]
                params["pubStartDate"] = date_str

            # 添加关键词搜索（API 2.0 支持）
            if keyword and use_api_v2:
                params["keywordSearch"] = keyword
                logger.info(f"   关键词搜索: {keyword}")

        try:
            # 使用代理和 SSL 验证
            # 如果使用代理，禁用 SSL 验证；否则使用证书验证
            verify_ssl = not USE_PROXY

            # 尝试请求（最多重试 3 次）
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    proxies = PROXIES or None
                    timeout = httpx.Timeout(30.0)
                    with httpx.Client(
                        proxies=proxies,
                        verify=verify_ssl,
                        timeout=timeout,
                        follow_redirects=False,
                    ) as client:
                        response = client.get(
                            api_base,
                            params=params,
                            headers=headers,
                        )
                    response.raise_for_status()
                    return response.json()
                except httpx.ConnectError:
                    if attempt < max_retries - 1:
                        logger.warning(
                            f"⚠️ 连接错误（尝试 {attempt + 1}/{max_retries}），将重试...",
                        )
                        continue
                    raise
                except httpx.HTTPError as e:
                    # 对于 SSL 或其他 HTTP 错误，若还有重试次数则禁用 SSL 验证后重试一次
                    if isinstance(e, httpx.TransportError) and attempt < max_retries - 1:
                        logger.warning(
                            f"⚠️ 传输错误（尝试 {attempt + 1}/{max_retries}），禁用 SSL 验证重试...",
                        )
                        verify_ssl = False
                        continue
                    raise

        except httpx.HTTPError as e:
            logger.error(f"❌ API 请求失败: {e}")
            if "response" in locals():
                logger.error("   URL: %s", response.url)
                logger.error("   状态码: %s", getattr(response, "status_code", "unknown"))
                logger.error("   响应: %s", response.text[:200])
            else:
                logger.error("   URL: %s", api_base)
            if use_api_v2:
                logger.error("   提示: 如果使用 API 2.0，请检查 NVD_API_KEY 是否正确")
            return {}

    def parse_cve_data(self, cve_item: dict) -> dict | None:
        """
        解析单个 CVE 数据（支持 API 1.0 和 2.0）

        Args:
            cve_item: CVE 原始数据

        Returns:
            解析后的结构化数据
        """
        try:
            # API 2.0 格式
            if "id" in cve_item:
                cve_id = cve_item.get("id", "")
                descriptions = cve_item.get("descriptions", [])
                metrics = cve_item.get("metrics", {})
                published = cve_item.get("published", "")
                weaknesses = cve_item.get("weaknesses", [])
            # API 1.0 格式
            else:
                cve_id = cve_item.get("CVE_data_meta", {}).get("ID", "")
                descriptions = cve_item.get("description", {}).get("description_data", [])
                metrics = cve_item.get("impact", {})
                published = cve_item.get("publishedDate", "")
                weaknesses = cve_item.get("cve", {}).get("problemtype", {}).get("problemtype_data", [])

            # 获取英文描述
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en" or desc.get("lang") == "en-US":
                    description = desc.get("value", "") or desc.get("description", "")
                    break

            # 获取严重程度和 CVSS 分数
            severity = "Unknown"
            cvss_score = 0.0

            # API 2.0 格式
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0]
                severity = cvss_data.get("cvssData", {}).get("baseSeverity", "Unknown")
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0]
                severity = cvss_data.get("baseSeverity", "Unknown")
                cvss_score = cvss_data.get("cvssData", {}).get("baseScore", 0.0)
            # API 1.0 格式
            elif "baseMetricV3" in metrics:
                cvss_data = metrics.get("baseMetricV3", {})
                severity = cvss_data.get("cvssV3", {}).get("baseSeverity", "Unknown")
                cvss_score = cvss_data.get("cvssV3", {}).get("baseScore", 0.0)
            elif "baseMetricV2" in metrics:
                cvss_data = metrics.get("baseMetricV2", {})
                severity_map = {"LOW": "Low", "MEDIUM": "Medium", "HIGH": "High"}
                severity = severity_map.get(cvss_data.get("severity", ""), "Unknown")
                cvss_score = cvss_data.get("cvssV2", {}).get("baseScore", 0.0)

            # 获取 CWE ID
            cwe_ids = []
            if weaknesses:
                # API 2.0 格式
                if isinstance(weaknesses, list) and len(weaknesses) > 0:
                    for weakness in weaknesses[0].get("description", []):
                        if weakness.get("lang") == "en":
                            cwe_id = weakness.get("value", "")
                            if cwe_id.startswith("CWE-"):
                                cwe_ids.append(cwe_id)
                # API 1.0 格式
                elif isinstance(weaknesses, list):
                    for weakness_group in weaknesses:
                        for desc in weakness_group.get("description", []):
                            cwe_id = desc.get("value", "")
                            if cwe_id and cwe_id.startswith("CWE-"):
                                cwe_ids.append(cwe_id)

            return {
                "id": cve_id,
                "description": description,
                "severity": severity,
                "cvss_score": cvss_score,
                "published": published,
                "cwe_ids": cwe_ids,
                "raw_data": cve_item,
            }
        except Exception as e:
            logger.error(f"❌ 解析 CVE 数据失败: {e}")
            return None

    def format_document(self, cve_data: dict) -> str:
        """
        格式化 CVE 数据为文档字符串（用于向量化）

        Args:
            cve_data: CVE 数据

        Returns:
            格式化的文档字符串
        """
        parts = [
            f"漏洞编号: {cve_data['id']}",
            f"摘要: {cve_data['description'][:200]}",
            f"严重程度: {cve_data['severity']}",
            f"CVSS 分数: {cve_data['cvss_score']}",
        ]

        if cve_data["cwe_ids"]:
            parts.append(f"CWE: {', '.join(cve_data['cwe_ids'])}")

        return "; ".join(parts)

    def crawl_recent_cves(self, days: int = 7, max_results: int = 100, keyword: str | None = None) -> list[dict]:
        """
        爬取最近 N 天的 CVE 数据

        Args:
            days: 最近多少天
            max_results: 最多获取多少条
            keyword: 关键词搜索（可选，用于过滤特定语言的 CVE）

        Returns:
            CVE 数据列表
        """
        # 计算起始和结束日期
        end_date = datetime.now()
        start_date = end_date - timedelta(days=days)
        pub_start_date = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
        pub_end_date = end_date.strftime("%Y-%m-%dT23:59:59.000Z")

        if keyword:
            logger.info(f"🔍 开始爬取最近 {days} 天包含 '{keyword}' 的 CVE 数据...")
        else:
            logger.info(
                f"🔍 开始爬取最近 {days} 天的 CVE 数据（从 {start_date.strftime('%Y-%m-%d')} 到 {end_date.strftime('%Y-%m-%d')}）..."
            )

        all_cves = []
        start_index = 0

        while len(all_cves) < max_results:
            # 请求数据
            response = self.fetch_cves_from_nvd(
                start_index=start_index,
                results_per_page=BATCH_SIZE,
                pub_start_date=pub_start_date,
                pub_end_date=pub_end_date,
                keyword=keyword,  # 添加关键词参数
            )

            # API 1.0 和 2.0 的响应格式不同
            if not response:
                logger.warning("⚠️ 没有更多数据")
                break

            # API 2.0 格式
            if "vulnerabilities" in response:
                vulnerabilities = response.get("vulnerabilities", [])
            # API 1.0 格式
            elif "result" in response:
                vulnerabilities = response.get("result", {}).get("CVE_Items", [])
                # 转换为统一格式
                vulnerabilities = [{"cve": item} for item in vulnerabilities]
            else:
                logger.warning("⚠️ 响应格式未知")
                break

            if not vulnerabilities:
                break

            # 解析数据
            for vuln in vulnerabilities:
                # API 1.0 和 2.0 的数据结构不同
                if "cve" in vuln:
                    cve_item = vuln["cve"]
                else:
                    cve_item = vuln

                cve_data = self.parse_cve_data(cve_item)
                if cve_data:
                    all_cves.append(cve_data)

            logger.info(f"📊 已获取 {len(all_cves)} 条 CVE 数据...")

            # 检查是否还有更多数据
            # API 1.0 和 2.0 的格式不同
            if "totalResults" in response:
                total_results = response.get("totalResults", 0)
            elif "result" in response:
                total_results = response.get("result", {}).get("totalResults", 0)
            else:
                total_results = len(vulnerabilities)

            if start_index + BATCH_SIZE >= total_results:
                break

            start_index += BATCH_SIZE
            time.sleep(1)  # 避免请求过快

        logger.info(f"✅ 共获取 {len(all_cves)} 条 CVE 数据")
        return all_cves[:max_results]

    def update_database(self, cve_list: list[dict], incremental: bool = True):
        """
        更新数据库

        Args:
            cve_list: CVE 数据列表
            incremental: 是否增量更新（只添加新的）
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
        update_count = 0

        for cve_data in cve_list:
            cve_id = cve_data["id"]

            # 增量更新：跳过已存在的
            if incremental and cve_id in existing_ids:
                continue

            ids.append(cve_id)
            documents.append(self.format_document(cve_data))
            metadatas.append(
                {
                    "severity": cve_data["severity"],
                    "cvss_score": cve_data["cvss_score"],
                    "published": cve_data["published"],
                    "cwe_ids": ",".join(cve_data["cwe_ids"]),
                    "source": "NVD_API",
                    "crawled_at": datetime.now().isoformat(),
                }
            )

            if cve_id in existing_ids:
                update_count += 1
            else:
                new_count += 1

        if not ids:
            logger.info("ℹ️ 没有新数据需要添加")
            return

        # 写入数据库
        logger.info(f"💾 正在写入数据库：{new_count} 条新增，{update_count} 条更新...")
        self.collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
        logger.info(f"✅ 数据库更新完成！当前共有 {self.collection.count()} 条记录")

    def run(self, days: int = 7, max_results: int = 100, incremental: bool = True):
        """
        运行爬虫

        Args:
            days: 爬取最近多少天
            max_results: 最多获取多少条
            incremental: 是否增量更新
        """
        logger.info("=" * 70)
        logger.info("🚀 CVE 数据爬虫启动")
        logger.info("=" * 70)

        start_time = time.time()

        # 爬取数据
        cve_list = self.crawl_recent_cves(days=days, max_results=max_results)

        # 更新数据库
        self.update_database(cve_list, incremental=incremental)

        # 保存更新时间
        self.save_update_time(datetime.now())

        elapsed = time.time() - start_time
        logger.info(f"⏱️ 总耗时: {elapsed:.2f} 秒")
        logger.info("=" * 70)


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description="CVE 数据爬虫（支持自动化）")
    parser.add_argument("--days", type=int, default=7, help="爬取最近多少天（默认：7）")
    parser.add_argument("--max-results", type=int, default=100, help="最多获取多少条（默认：100）")
    parser.add_argument("--full", action="store_true", help="全量更新（不增量）")
    parser.add_argument("--auto", action="store_true", help="自动模式（从上次更新时间开始）")

    args = parser.parse_args()

    crawler = CVECrawler()

    if args.auto:
        # 自动模式：从上次更新时间开始
        last_update = crawler.get_last_update_time()
        if last_update:
            days = (datetime.now() - last_update).days + 1
            logger.info(f"🔄 自动模式：从上次更新（{last_update.strftime('%Y-%m-%d')}）开始，共 {days} 天")
        else:
            days = args.days
            logger.info(f"🔄 自动模式：首次运行，爬取最近 {days} 天")
    else:
        days = args.days

    crawler.run(days=days, max_results=args.max_results, incremental=not args.full)


if __name__ == "__main__":
    main()
