"""
conftest.py - pytest 共享 Fixture

自动将项目根目录加入 sys.path，所有测试文件无需重复设置。
"""

import os
import sys
from pathlib import Path

# 将 aegis-ai-core 添加到 Python 路径
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# 排除「不是真正 pytest 用例」的脚本文件，避免 pytest 收集时 INTERNALERROR：
#   - test_vulnerable_code.py：漏洞代码样本文件，含 input() 等副作用
#   - test_api_direct.py：独立脚本，依赖未安装的 aegis_server
#   - test_embedding_models.py：已在文件内用 pytest.skip 处理，此处兜底
collect_ignore = [
    "test_vulnerable_code.py",
    "test_api_direct.py",
]
