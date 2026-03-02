# cve_crawler_scheduler.py - CVE 爬虫定时任务调度器
"""
定时任务调度器：
- Windows: 使用任务计划程序（Task Scheduler）
- Linux/Mac: 使用 cron
- Python: 使用 schedule 库（跨平台）
"""
import schedule
import time
import logging
from src.crawler.cve_crawler_auto import CVECrawler

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def run_daily_update():
    """每天运行一次更新"""
    logger.info("⏰ 定时任务触发：每日更新")
    crawler = CVECrawler()
    crawler.run(days=1, max_results=50, incremental=True)


def run_weekly_update():
    """每周运行一次更新"""
    logger.info("⏰ 定时任务触发：每周更新")
    crawler = CVECrawler()
    crawler.run(days=7, max_results=200, incremental=True)


def main():
    """主函数：启动定时任务"""
    logger.info("="*70)
    logger.info("🕐 CVE 爬虫定时任务调度器启动")
    logger.info("="*70)
    
    # 配置定时任务
    # 每天凌晨 2 点运行
    schedule.every().day.at("02:00").do(run_daily_update)
    
    # 或者每周一凌晨 3 点运行（可选）
    # schedule.every().monday.at("03:00").do(run_weekly_update)
    
    logger.info("📅 定时任务已配置：")
    logger.info("   - 每天 02:00 自动更新 CVE 数据")
    logger.info("   - 按 Ctrl+C 停止")
    logger.info("="*70)
    
    # 运行调度器
    try:
        while True:
            schedule.run_pending()
            time.sleep(60)  # 每分钟检查一次
    except KeyboardInterrupt:
        logger.info("\n👋 定时任务已停止")


if __name__ == "__main__":
    main()
