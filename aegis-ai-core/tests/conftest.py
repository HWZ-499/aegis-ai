"""
conftest.py - pytest 共享 Fixture

自动将项目根目录加入 sys.path，所有测试文件无需重复设置。
"""

import sys
from pathlib import Path

# 将 aegis-ai-core 添加到 Python 路径
_project_root = Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

# 排除「不是真正 pytest 用例」的脚本文件，避免 pytest 收集时 INTERNALERROR：
#   - test_vulnerable_code.py：漏洞代码样本文件，含 input() 等副作用
collect_ignore = [
    "test_vulnerable_code.py",
]
