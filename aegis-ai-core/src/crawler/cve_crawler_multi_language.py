# cve_crawler_multi_language.py - 多语言 CVE 数据爬虫
"""
扩展 CVE 爬虫，专门爬取不同编程语言的漏洞信息
"""

from datetime import datetime, timedelta

from src.crawler.cve_crawler_auto import CVECrawler

# 不同编程语言的关键词（用于 CVE 检索）
LANGUAGE_KEYWORDS = {
    "python": ["Python", "Django", "Flask", "pip", "PyPI"],
    "javascript": ["JavaScript", "Node.js", "npm", "Express", "React", "Vue"],
    "java": ["Java", "Spring", "Maven", "Gradle", "Apache"],
    "cpp": ["C++", "C/C++", "CVE", "buffer overflow"],
    "c": ["C", "C/C++", "CVE", "buffer overflow"],
    "go": ["Go", "Golang", "GoLang"],
    "php": ["PHP", "WordPress", "Laravel", "Composer"],
    "ruby": ["Ruby", "Rails", "Ruby on Rails", "gem"],
    "rust": ["Rust", "Cargo"],
    "swift": ["Swift", "iOS", "macOS"],
    "kotlin": ["Kotlin", "Android"],
    "csharp": ["C#", "ASP.NET", ".NET", "NuGet"],
}


class MultiLanguageCVECrawler(CVECrawler):
    """
    多语言 CVE 爬虫

    扩展原有爬虫，专门爬取不同编程语言的漏洞信息
    """

    def __init__(self, db_path: str = "./data/aegis_db", collection_name: str = "cve_core"):
        """
        初始化多语言 CVE 爬虫

        Args:
            db_path: 数据库路径
            collection_name: 集合名称
        """
        super().__init__(db_path, collection_name)
        self.language_keywords = LANGUAGE_KEYWORDS

    def crawl_language_specific_cves(self, language: str, days: int = 30) -> int:
        """
        爬取特定语言的 CVE 数据

        Args:
            language: 编程语言（python, javascript, java 等）
            days: 爬取最近多少天的数据

        Returns:
            爬取到的 CVE 数量
        """
        if language not in self.language_keywords:
            print(f"⚠️ 不支持的语言: {language}")
            return 0

        keywords = self.language_keywords[language]
        print(f"🔍 开始爬取 {language} 相关的 CVE 数据...")
        print(f"   关键词: {', '.join(keywords)}")

        total_count = 0

        # 为每个关键词爬取数据
        for keyword in keywords:
            print(f"\n   搜索关键词: {keyword}")

            # 计算日期范围
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)

            # 爬取数据
            try:
                cves = self.crawl_recent_cves(
                    days=days,
                    max_results=50,  # 每个关键词最多 50 条
                    keyword=keyword,  # 添加关键词过滤
                )
                count = len(cves)
                total_count += count
                print(f"   ✅ 找到 {count} 条相关 CVE")
            except (ConnectionError, TimeoutError, RuntimeError, ValueError) as e:
                print(f"   ❌ 爬取失败: {e}")
                import traceback

                traceback.print_exc()

        print(f"\n✅ {language} 语言 CVE 爬取完成，共 {total_count} 条")
        return total_count

    def crawl_all_languages(self, days: int = 30) -> dict[str, int]:
        """
        爬取所有支持语言的 CVE 数据

        Args:
            days: 爬取最近多少天的数据

        Returns:
            各语言的 CVE 数量统计
        """
        results = {}

        print("=" * 70)
        print("🌐 多语言 CVE 数据爬取")
        print("=" * 70)

        for language in self.language_keywords.keys():
            count = self.crawl_language_specific_cves(language, days)
            results[language] = count

        print("\n" + "=" * 70)
        print("📊 爬取统计")
        print("=" * 70)
        for language, count in results.items():
            print(f"   {language:15} : {count:4} 条")

        return results


if __name__ == "__main__":
    # 测试代码
    crawler = MultiLanguageCVECrawler()

    # 爬取 Python 相关的 CVE
    print("测试：爬取 Python 相关 CVE")
    count = crawler.crawl_language_specific_cves("python", days=7)
    print(f"\n✅ 爬取完成，共 {count} 条 Python 相关 CVE")
