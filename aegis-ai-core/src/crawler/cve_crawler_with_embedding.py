# cve_crawler_with_embedding.py - 使用自定义向量化的 CVE 爬虫
"""
使用自定义向量化模型的 CVE 爬虫版本

特点：
- 使用 sentence-transformers 进行向量化
- 不依赖 ChromaDB 的默认 embedding
- 可以选择更适合的模型
"""
import os
import sys

# 加载环境变量
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from src.crawler.cve_crawler_auto import CVECrawler
from src.rag.local_embedding import LocalEmbedder, get_global_embedder, SENTENCE_TRANSFORMERS_AVAILABLE
import chromadb
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class CVECrawlerWithCustomEmbedding(CVECrawler):
    """
    使用自定义向量化的 CVE 爬虫
    
    继承自 CVECrawler，但使用自定义向量化模型
    """
    
    def __init__(self, db_path: str = "./aegis_db", collection_name: str = "cve_core", 
                 embedding_model: str = "paraphrase-multilingual-MiniLM-L12-v2"):
        """
        初始化爬虫（使用自定义向量化）
        
        Args:
            db_path: ChromaDB 数据库路径
            collection_name: 集合名称
            embedding_model: 向量化模型名称
        """
        # 初始化向量化器
        if SENTENCE_TRANSFORMERS_AVAILABLE:
            self.embedder = LocalEmbedder(embedding_model)
            if not self.embedder.model:
                logger.warning("⚠️ 向量化模型加载失败，将使用 ChromaDB 默认向量化")
                self.embedder = None
        else:
            logger.warning("⚠️ sentence-transformers 未安装，将使用 ChromaDB 默认向量化")
            self.embedder = None
        
        # 初始化父类（不使用自定义向量化）
        super().__init__(db_path, collection_name)
        
        # 如果向量化器可用，重新创建集合（使用自定义向量）
        if self.embedder and self.embedder.model:
            logger.info(f"🔄 使用自定义向量化模型: {embedding_model}")
            # 注意：ChromaDB 的集合一旦创建，embedding 函数就固定了
            # 如果需要使用自定义向量，需要在创建集合时指定
            # 这里我们只是记录使用的模型
            try:
                # 尝试获取集合的元数据
                metadata = self.collection.metadata or {}
                metadata['embedding_model'] = embedding_model
                logger.info(f"📝 集合元数据: {metadata}")
            except:
                pass
    
    def update_database_with_custom_embedding(self, cve_list, incremental: bool = True):
        """
        使用自定义向量化更新数据库
        
        Args:
            cve_list: CVE 数据列表
            incremental: 是否增量更新
        """
        if not self.embedder or not self.embedder.model:
            # 降级到默认方法
            logger.info("ℹ️ 使用 ChromaDB 默认向量化")
            return super().update_database(cve_list, incremental)
        
        if not cve_list:
            logger.warning("⚠️ 没有数据需要更新")
            return
        
        # 获取现有 ID
        existing_ids = set()
        if incremental:
            try:
                existing_data = self.collection.get()
                existing_ids = set(existing_data.get('ids', []))
            except:
                pass
        
        # 准备数据
        ids = []
        documents = []
        metadatas = []
        texts_to_embed = []
        
        new_count = 0
        
        for cve_data in cve_list:
            cve_id = cve_data['id']
            
            if incremental and cve_id in existing_ids:
                continue
            
            ids.append(cve_id)
            doc = self.format_document(cve_data)
            documents.append(doc)
            texts_to_embed.append(doc)
            metadatas.append({
                'severity': cve_data.get('severity', 'Unknown'),
                'cvss_score': str(cve_data.get('cvss_score', 0.0)),
                'published': cve_data.get('published', ''),
                'cwe_ids': ','.join(cve_data.get('cwe_ids', [])),
                'source': 'NVD_API',
                'crawled_at': self._get_current_time().isoformat()
            })
            new_count += 1
        
        if not ids:
            logger.info("ℹ️ 没有新数据需要添加")
            return
        
        # 使用自定义向量化
        logger.info(f"🔄 使用自定义模型向量化 {len(texts_to_embed)} 个文档...")
        embeddings = self.embedder.encode(texts_to_embed, show_progress=True)
        embeddings_list = embeddings.tolist()
        
        # 写入数据库（使用自定义向量）
        logger.info(f"💾 正在写入数据库：{new_count} 条新增...")
        self.collection.upsert(
            ids=ids,
            embeddings=embeddings_list,  # 使用自定义向量
            documents=documents,
            metadatas=metadatas
        )
        logger.info(f"✅ 数据库更新完成！当前共有 {self.collection.count()} 条记录")
    
    def _get_current_time(self):
        """获取当前时间（用于元数据）"""
        from datetime import datetime
        return datetime.now()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='使用自定义向量化的 CVE 爬虫')
    parser.add_argument('--days', type=int, default=7, help='爬取最近多少天')
    parser.add_argument('--max-results', type=int, default=100, help='最多获取多少条')
    parser.add_argument('--model', type=str, default='paraphrase-multilingual-MiniLM-L12-v2',
                       help='向量化模型名称')
    parser.add_argument('--auto', action='store_true', help='自动模式')
    parser.add_argument('--full', action='store_true', help='全量更新')
    
    args = parser.parse_args()
    
    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        logger.error("❌ sentence-transformers 未安装")
        logger.info("   安装命令: pip install sentence-transformers")
        logger.info("   或者使用默认版本: python cve_crawler_auto.py")
        return
    
    crawler = CVECrawlerWithCustomEmbedding(embedding_model=args.model)
    
    if args.auto:
        from datetime import datetime
        last_update = crawler.get_last_update_time()
        if last_update:
            days = (datetime.now() - last_update).days + 1
        else:
            days = args.days
    else:
        days = args.days
    
    # 爬取数据
    cve_list = crawler.crawl_recent_cves(days=days, max_results=args.max_results)
    
    # 使用自定义向量化更新数据库
    if crawler.embedder and crawler.embedder.model:
        crawler.update_database_with_custom_embedding(cve_list, incremental=not args.full)
    else:
        crawler.update_database(cve_list, incremental=not args.full)
    
    crawler.save_update_time(datetime.now())


if __name__ == "__main__":
    main()
