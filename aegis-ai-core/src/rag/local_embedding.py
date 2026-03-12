# local_embedding.py - 本地向量化流程（使用 sentence-transformers）
"""
本地向量化模块：
1. 使用 sentence-transformers（本地模型，不需要 API）
2. 支持多种 embedding 模型
3. 可以对比不同模型的效果
4. 不依赖 ChromaDB 的自动向量化
"""

import logging

import numpy as np

logger = logging.getLogger(__name__)

# 尝试导入 sentence-transformers
try:
    from sentence_transformers import SentenceTransformer

    SENTENCE_TRANSFORMERS_AVAILABLE = True
except ImportError:
    SENTENCE_TRANSFORMERS_AVAILABLE = False
    logger.warning(
        "sentence-transformers 未安装，将使用 ChromaDB 默认向量化。安装命令: pip install sentence-transformers"
    )

# 默认模型（中文友好）
DEFAULT_MODEL = "paraphrase-multilingual-MiniLM-L12-v2"  # 支持多语言，包括中文
# 备选模型：
# - "all-MiniLM-L6-v2"：英文，速度快
# - "paraphrase-multilingual-MiniLM-L12-v2"：多语言，包括中文
# - "distiluse-base-multilingual-cased"：多语言，质量更高但更慢


class LocalEmbedder:
    """
    本地向量化器（使用 sentence-transformers）

    特点：
    - 完全离线，不需要 API
    - 可以自定义模型
    - 支持批量向量化
    """

    def __init__(self, model_name: str = DEFAULT_MODEL):
        """
        初始化向量化器

        Args:
            model_name: sentence-transformers 模型名称
        """
        self.model_name = model_name
        self.model: SentenceTransformer | None = None

        if SENTENCE_TRANSFORMERS_AVAILABLE:
            try:
                logger.info(f"📥 正在加载向量化模型: {model_name}...")
                self.model = SentenceTransformer(model_name)
                logger.info(f"✅ 模型加载成功！向量维度: {self.model.get_sentence_embedding_dimension()}")
            except (ImportError, OSError, RuntimeError) as e:
                logger.error(f"❌ 模型加载失败: {e}")
                logger.info("💡 将使用 ChromaDB 默认向量化")
                self.model = None
        else:
            logger.warning("⚠️ sentence-transformers 未安装，无法使用本地向量化")

    def encode(self, texts: list[str], batch_size: int = 32, show_progress: bool = False) -> np.ndarray:
        """
        将文本列表转换为向量

        Args:
            texts: 文本列表
            batch_size: 批量大小
            show_progress: 是否显示进度

        Returns:
            向量数组 (n_samples, embedding_dim)
        """
        if not self.model:
            raise RuntimeError("模型未加载，无法向量化")

        if isinstance(texts, str):
            texts = [texts]

        try:
            embeddings = self.model.encode(
                texts, batch_size=batch_size, show_progress_bar=show_progress, convert_to_numpy=True
            )
            return embeddings
        except (RuntimeError, ValueError) as e:
            logger.error(f"❌ 向量化失败: {e}")
            raise

    def encode_single(self, text: str) -> np.ndarray:
        """
        将单个文本转换为向量

        Args:
            text: 文本字符串

        Returns:
            向量数组 (embedding_dim,)
        """
        return self.encode([text])[0]

    def get_embedding_dimension(self) -> int:
        """
        获取向量维度

        Returns:
            向量维度
        """
        if self.model:
            return self.model.get_sentence_embedding_dimension()
        return 384  # 默认维度（如果模型未加载）


class EmbeddingModelComparator:
    """
    向量化模型对比器

    用于对比不同 embedding 模型的效果
    """

    def __init__(self, model_names: list[str]):
        """
        初始化对比器

        Args:
            model_names: 要对比的模型名称列表
        """
        self.models = {}
        for name in model_names:
            try:
                embedder = LocalEmbedder(name)
                if embedder.model:
                    self.models[name] = embedder
                    logger.info(f"✅ 模型 {name} 加载成功")
            except (ImportError, OSError, RuntimeError) as e:
                logger.warning(f"⚠️ 模型 {name} 加载失败: {e}")

    def compare_embeddings(self, text: str) -> dict[str, np.ndarray]:
        """
        使用不同模型对同一文本进行向量化

        Args:
            text: 输入文本

        Returns:
            字典：{模型名: 向量}
        """
        results = {}
        for name, embedder in self.models.items():
            try:
                vector = embedder.encode_single(text)
                results[name] = vector
            except (RuntimeError, ValueError) as e:
                logger.error(f"❌ 模型 {name} 向量化失败: {e}")

        return results

    def compare_similarity(self, text1: str, text2: str) -> dict[str, float]:
        """
        对比不同模型计算的文本相似度

        Args:
            text1: 文本 1
            text2: 文本 2

        Returns:
            字典：{模型名: 相似度分数}
        """
        from sklearn.metrics.pairwise import cosine_similarity

        results = {}
        for name, embedder in self.models.items():
            try:
                vec1 = embedder.encode_single(text1)
                vec2 = embedder.encode_single(text2)
                similarity = cosine_similarity([vec1], [vec2])[0][0]
                results[name] = float(similarity)
            except (RuntimeError, ValueError) as e:
                logger.error(f"❌ 模型 {name} 相似度计算失败: {e}")

        return results


def create_chromadb_collection_with_custom_embedding(
    client,
    collection_name: str,
    embedder: LocalEmbedder,
    documents: list[str],
    ids: list[str],
    metadatas: list[dict] | None = None,
):
    """
    使用自定义向量化模型创建 ChromaDB 集合

    Args:
        client: ChromaDB 客户端
        collection_name: 集合名称
        embedder: 本地向量化器
        documents: 文档列表
        ids: ID 列表
        metadatas: 元数据列表（可选）

    Returns:
        ChromaDB 集合对象
    """
    if not embedder.model:
        raise RuntimeError("向量化器未初始化")

    # 生成向量
    logger.info(f"🔄 正在向量化 {len(documents)} 个文档...")
    embeddings = embedder.encode(documents, show_progress=True)

    # 转换为列表格式（ChromaDB 需要）
    embeddings_list = embeddings.tolist()

    # 创建集合（使用自定义向量）
    collection = client.create_collection(name=collection_name, metadata={"embedding_model": embedder.model_name})

    # 添加数据（使用自定义向量）
    collection.add(
        ids=ids, embeddings=embeddings_list, documents=documents, metadatas=metadatas or [{}] * len(documents)
    )

    logger.info(f"✅ 集合创建成功，使用模型: {embedder.model_name}")
    return collection


# 全局向量化器实例（懒加载）
_global_embedder: LocalEmbedder | None = None


def get_global_embedder(model_name: str = DEFAULT_MODEL) -> LocalEmbedder | None:
    """
    获取全局向量化器实例（单例模式）

    Args:
        model_name: 模型名称

    Returns:
        向量化器实例，如果未安装则返回 None
    """
    global _global_embedder

    if not SENTENCE_TRANSFORMERS_AVAILABLE:
        return None

    if _global_embedder is None or _global_embedder.model_name != model_name:
        _global_embedder = LocalEmbedder(model_name)

    return _global_embedder if _global_embedder.model else None
