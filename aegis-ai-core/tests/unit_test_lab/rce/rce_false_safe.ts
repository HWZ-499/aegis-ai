/**
 * RCE假漏洞测试用例（应该不报告）
 * 
 * 场景：硬编码字符串传递给eval()，不是用户输入
 * 预期：不应该报告漏洞
 */

// 假漏洞：硬编码字符串，安全
eval("console.log('Hello World')");

// 假漏洞：硬编码字符串，安全
const func = new Function("return 1 + 1");
const result = func();

// 假漏洞：常量字符串，安全
const safeCode = "Math.max(1, 2, 3)";
eval(safeCode);
