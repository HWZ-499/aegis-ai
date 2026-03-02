# 🚀 快速安装本地向量化依赖

## 📋 安装步骤

### 方法 1：使用 pip（推荐）

```bash
cd aegis-ai-core
pip install sentence-transformers scikit-learn
```

**注意**：
- 首次安装会自动下载模型（约 100-500 MB）
- 需要稳定的网络连接
- 安装时间：5-10 分钟

### 方法 2：使用 requirements.txt

```bash
cd aegis-ai-core
pip install -r requirements.txt
```

---

## 🧪 测试安装

```bash
python test_embedding_models.py
```

**如果成功**，你会看到：
```
✅ sentence-transformers 已安装
✅ 模型加载成功
   向量维度: 384
✅ 向量化完成
```

---

## 💡 使用建议

### 当前状态

- ✅ **代码已实现**：本地向量化模块已完成
- ⏳ **依赖未安装**：需要安装 sentence-transformers

### 两种使用方式

#### 方式 1：使用 ChromaDB 默认向量化（当前）

**优点**：
- ✅ 无需安装额外依赖
- ✅ 开箱即用

**缺点**：
- ❌ 模型不可控
- ❌ 可能不适合中文

**使用**：
```bash
python cve_crawler_auto.py --days 7 --max-results 100
```

#### 方式 2：使用自定义向量化（推荐，需要安装依赖）

**优点**：
- ✅ 模型可控
- ✅ 支持多语言（中文友好）
- ✅ 可以对比不同模型

**缺点**：
- ⚠️ 需要安装依赖
- ⚠️ 首次使用需要下载模型

**使用**：
```bash
# 1. 安装依赖
pip install sentence-transformers scikit-learn

# 2. 使用自定义向量化
python cve_crawler_with_embedding.py --days 7 --max-results 100
```

---

## 📊 对比

| 特性 | ChromaDB 默认 | 自定义向量化 |
|------|--------------|-------------|
| 安装难度 | ⭐ 简单 | ⭐⭐ 需要安装依赖 |
| 模型可控 | ❌ | ✅ |
| 中文支持 | ⚠️ 一般 | ✅ 好（多语言模型） |
| 技术深度 | 6/10 | 9/10 |

---

## 🎯 推荐

**当前阶段**：
- ✅ 代码已实现，随时可以使用
- ✅ 如果不需要自定义向量化，可以继续使用 ChromaDB 默认

**生产环境**：
- ✅ 推荐安装 sentence-transformers
- ✅ 使用多语言模型（中文友好）
- ✅ 提高向量化质量

---

**提示**：本地向量化是可选的优化，不影响核心功能！
