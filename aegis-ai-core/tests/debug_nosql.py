"""
调试 NoSQL 规则
"""
import sys
from pathlib import Path

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from tree_sitter import Parser, Node
from tree_sitter_languages import get_language

# 测试代码
code = """
usersCol.findOne({ userName: userName }, callback);
"""

# 解析AST
js_lang = get_language("javascript")
parser = Parser()
parser.set_language(js_lang)
tree = parser.parse(bytes(code, "utf8"))

def print_node(node: Node, indent=0):
    """打印AST节点"""
    prefix = "  " * indent
    print(f"{prefix}{node.type}: {node.text.decode('utf-8') if hasattr(node, 'text') else ''}")
    for child in node.children:
        print_node(child, indent + 1)

print("AST结构:")
print_node(tree.root_node)

print("\n查找 call_expression:")
def find_call_expressions(node: Node):
    if node.type == "call_expression":
        print(f"\n找到 call_expression:")
        print_node(node)
        # 检查第一个子节点（callee）
        if node.children:
            callee = node.children[0]
            print(f"\nCallee类型: {callee.type}")
            print_node(callee)
    for child in node.children:
        find_call_expressions(child)

find_call_expressions(tree.root_node)
