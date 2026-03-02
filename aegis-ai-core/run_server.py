#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
启动脚本 - 用于启动 Aegis 服务器
"""
import os
import sys

# 添加项目根目录到 Python 路径
_current_dir = os.path.dirname(os.path.abspath(__file__))
if _current_dir not in sys.path:
    sys.path.insert(0, _current_dir)

# 导入并运行服务器
if __name__ == "__main__":
    import uvicorn
    
    print("="*70)
    print("🚀 启动 Aegis 服务器")
    print("="*70)
    print(f"📁 工作目录: {os.getcwd()}")
    print(f"📦 项目根目录: {_current_dir}")
    print("="*70)
    
    # 使用字符串形式传递应用，支持 reload
    uvicorn.run("src.server.aegis_server:app", host="0.0.0.0", port=8000, reload=True)
