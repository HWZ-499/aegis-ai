/**
 * RCE真漏洞测试用例
 * 
 * 场景：用户输入直接传递给eval()执行
 * 预期：应该报告 RCE_COMMAND_EXEC (Critical)
 */

// 从HTTP请求获取用户输入
const userInput = req.body.code;

// 真漏洞：用户输入直接执行
eval(userInput);

// 另一个真漏洞：用户输入直接执行命令
const { exec } = require('child_process');
exec(userInput);

// 真漏洞：new Function()执行用户输入
const func = new Function(userInput);
func();
