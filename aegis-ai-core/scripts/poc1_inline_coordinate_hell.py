#!/usr/bin/env python3
"""
PoC 1: 内联 (Inlining) 与「坐标地狱」

用 Python ast 解析两段简单函数，手动做一次“内联”，并打印内联后 AST 节点的行号。
用于验证 TDD 12.3：体会虚拟行号与原始源码的错位，以及维护
「虚拟节点 → (CallSite, DefinitionSite)」映射的必要性。

运行: 在 aegis-ai-core 下执行
  python scripts/poc1_inline_coordinate_hell.py
"""

import ast
from copy import deepcopy


# 模拟源码：第 10 行调用 unsafe，第 50 行定义 unsafe（Sink 在第 52 行）
SOURCE = '''
def get_input():
    return input("name: ")

def unsafe(user_data):
    result = eval(user_data)  # Sink 在“定义处”的第 52 行
    return result

def main():
    payload = get_input()     # 第 10 行：Source
    unsafe(payload)          # 第 11 行：调用点 CallSite
'''

# 为演示，我们给每行加行号注释，便于和下面输出对应（实际 SOURCE 从第 2 行开始）
# 行 2: 空
# 行 3: def get_input():
# ...
# 行 8: def unsafe(user_data):
# 行 9:     result = eval(user_data)
# 行 10:     return result
# ...
# 行 13: def main():
# 行 14:     payload = get_input()
# 行 15:     unsafe(payload)


def get_lineno(node: ast.AST) -> int:
    """获取节点行号，兼容无 lineno 的节点（如 Module）。"""
    return getattr(node, "lineno", 0)


def collect_nodes_with_lines(tree: ast.AST, prefix: str = "") -> list[tuple[str, int, str]]:
    """递归收集 AST 中所有带行号的节点，返回 (节点类型, 行号, 简要描述)。"""
    out = []
    for field, value in ast.iter_fields(tree):
        if isinstance(value, ast.AST):
            desc = f"{field}"
            if isinstance(value, (ast.Call, ast.Name, ast.FunctionDef)):
                if isinstance(value, ast.Call):
                    try:
                        fn = value.func
                        name = ast.get_source_segment(SOURCE, fn) or getattr(fn, "id", "?")
                    except Exception:
                        name = "?"
                    desc = f"Call({name})"
                elif isinstance(value, ast.Name):
                    desc = f"Name({value.id})"
                elif isinstance(value, ast.FunctionDef):
                    desc = f"FunctionDef({value.name})"
            ln = get_lineno(value)
            if ln:
                out.append((prefix + type(value).__name__, ln, desc))
            out.extend(collect_nodes_with_lines(value, prefix))
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST):
                    ln = get_lineno(item)
                    if ln:
                        out.append((prefix + type(item).__name__, ln, ""))
                    out.extend(collect_nodes_with_lines(item, prefix))
    return out


def main_poc():
    print("=" * 60)
    print("PoC 1: 内联与坐标地狱 (Source Map)")
    print("=" * 60)

    tree = ast.parse(SOURCE)
    lines = SOURCE.splitlines()

    # 1) 原始 AST 中的行号分布
    print("\n【1】原始源码中的关键行号（供对照）")
    print("     (SOURCE 字符串从“第 2 行”开始，因首行空)")
    for i, line in enumerate(lines, start=1):
        s = line.strip()
        if s and not s.startswith("#"):
            print(f"     行 {i:2d}: {s[:60]}")

    print("\n【2】原始 AST 中“带行号”的节点（仅列出关键类型）")
    nodes_original = collect_nodes_with_lines(tree)
    seen = set()
    for typ, ln, desc in nodes_original:
        if "Call" in typ or "Name" in typ or "FunctionDef" in typ or "eval" in desc:
            key = (typ, ln, desc)
            if key not in seen:
                seen.add(key)
                print(f"     {typ:20s}  lineno={ln:2d}  {desc}")

    # 2) 模拟内联：把 main() 里对 unsafe(payload) 的调用“展开”成 unsafe 的函数体
    #    展开后我们得到一段“虚拟 AST”，其节点行号有两种可能：
    #    A) 保留被内联函数体的原始行号（8,9,10） -> 报给用户的是“定义处”
    #    B) 重写为“调用处”的行号（15）       -> 报给用户的是“调用点”
    #    无论 A 还是 B，单独一种都无法同时表达“调用链 + 漏洞具体位置”

    main_func = None
    unsafe_func = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            if node.name == "main":
                main_func = node
            elif node.name == "unsafe":
                unsafe_func = node

    if not main_func or not unsafe_func:
        print("\n[ERROR] 未找到 main 或 unsafe 函数")
        return

    # 找到 main 里对 unsafe(...) 的调用
    call_unsafe_lineno = None
    for node in ast.walk(main_func):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id == "unsafe":
                call_unsafe_lineno = get_lineno(node)
                break

    print("\n【3】内联后的“坐标地狱”演示")
    print(f"     - 调用点 CallSite: main() 里调用 unsafe(payload) 所在行 = {call_unsafe_lineno}")
    print(f"     - 定义处 DefinitionSite: unsafe 函数体（含 eval）所在行 = {get_lineno(unsafe_func.body[0])} ~ {get_lineno(unsafe_func.body[-1])}")

    # 假设我们在“展开后的 AST”里发现了 Sink（eval）
    # 若我们只存了“虚拟树”的节点，该节点的 lineno 要么是 9（来自定义处），要么被我们改成 15（调用处）
    print("\n     -> 若分析器在「内联后的 AST」里发现漏洞（eval），应上报哪一行？")
    print("        - 只报 9:  用户看到的是 unsafe 内部的 eval，但不知道是 main 里哪次调用传入的脏数据")
    print("        - 只报 15: 用户看到的是 unsafe(payload)，看不到真正执行危险的 eval 在哪一行")
    print("        -> 结论: 必须维护 虚拟节点 -> (CallSite, DefinitionSite) 映射，上报时同时提供两处或按策略选主位置")

    # 4) 模拟“内联后的树”中某个节点（例如 Expr(Call(eval))）的行号
    eval_lineno_in_unsafe = get_lineno(unsafe_func.body[0])  # result = eval(user_data)
    print(f"\n【4】当前实现若不做映射：发现 Sink 的节点 lineno = {eval_lineno_in_unsafe}（定义处）")
    print(f"     IDE 会高亮到「定义处」第 {eval_lineno_in_unsafe} 行；若误用「调用处」行号则会高亮到第 {call_unsafe_lineno} 行（仅函数调用）。")
    print("     两者单独使用都会造成理解困难 -> 必须在内联时维护 Source Map。")

    print("\n" + "=" * 60)
    print("PoC 1 结论: 内联实现必须伴随 虚拟节点 -> (CallSite, DefinitionSite) 映射表。")
    print("=" * 60)


if __name__ == "__main__":
    main_poc()
