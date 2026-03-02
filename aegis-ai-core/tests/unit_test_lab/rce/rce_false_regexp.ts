/**
 * RCE假漏洞测试用例（应该不报告）
 * 
 * 场景：RegExp.exec()被误报为RCE
 * 预期：不应该报告漏洞，因为这是正则表达式方法，不是命令执行
 */

// 假漏洞：RegExp.exec() - 正则表达式方法，不是命令执行
const regex = /^rgb\((\d+),\s*(\d+),\s*(\d+)\)$/;
const match = regex.exec(colorString);

// 假漏洞：new RegExp().exec() - 正则表达式方法
const pattern = new RegExp('\\d+');
const result = pattern.exec(text);

// 假漏洞：变量名包含exec但不是命令执行
const regexp = /test/;
const execResult = regexp.exec(input);
