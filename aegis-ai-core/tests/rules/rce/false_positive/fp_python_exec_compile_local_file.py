"""
FP: exec(compile(local_file.read(), ...)) 属于本地配置加载模式，
在未出现用户输入污点时不应报 RCE_COMMAND_EXEC。
期望: 无 RCE_COMMAND_EXEC
"""


def from_pyfile(filename):
    with open(filename, mode="rb") as config_file:
        exec(compile(config_file.read(), filename, "exec"), {})
