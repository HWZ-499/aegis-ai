"""
Aegis AI LSP Server 入口点。

支持通过 ``python -m src.lsp`` 启动 Language Server。
"""

import warnings

# tree-sitter==0.21.3 内部使用旧版 Language(path, name) API，会产生 FutureWarning。
# 该警告无功能影响，但 stderr 噪音可能干扰 LSP stdio 通信解析，故在此过滤。
# 待 tree-sitter-languages 兼容 tree-sitter>=0.22 后再移除此行。
warnings.filterwarnings("ignore", category=FutureWarning, module="tree_sitter")

from .server import create_server


def main() -> None:
    """启动 LSP Server（stdio 模式）。"""
    server = create_server()
    server.start_io()


if __name__ == "__main__":
    main()
