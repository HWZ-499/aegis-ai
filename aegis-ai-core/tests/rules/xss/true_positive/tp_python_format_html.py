"""
TP: 调用 mark_safe 直接输出用户输入，存在 XSS 风险。
期望检测: XSS_RISK (High)
"""


def mark_safe(value: str) -> str:
    # 测试文件中的占位实现，仅用于让规则识别 sink 名称
    return value


def vulnerable_xss(user_input: str) -> str:
    # 用户输入未经任何转义直接传给 mark_safe
    return mark_safe(user_input)

