"""
FP: 字符串 "".join(...) 不是 os.path.join(...)，不应触发 PATH_TRAVERSAL。
期望: 无 PATH_TRAVERSAL
"""


def format_message(request):
    names = ", ".join(request.args.getlist("name"))
    return f"submitted: {names}"
