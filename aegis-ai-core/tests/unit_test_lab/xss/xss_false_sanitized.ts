/**
 * XSS假漏洞测试用例（应该不报告）
 * 
 * 场景：用户输入经过转义或使用安全方法输出
 * 预期：不应该报告漏洞
 */

// 从HTTP请求获取用户输入
const userInput = req.query.comment;

// 假漏洞：使用textContent，会自动转义，安全
document.getElementById('content').textContent = userInput;

// 假漏洞：使用htmlspecialchars转义，安全
const escaped = htmlspecialchars(userInput);
document.getElementById('content').innerHTML = escaped;

// 假漏洞：使用htmlentities转义，安全
const encoded = htmlentities(userInput);
document.getElementById('content').innerHTML = encoded;

// 假漏洞：使用DOMPurify清理，安全
import DOMPurify from 'dompurify';
const clean = DOMPurify.sanitize(userInput);
document.getElementById('content').innerHTML = clean;

// 假漏洞：React使用textContent，安全
const element = <div>{userInput}</div>; // React会自动转义

// 假漏洞：Vue使用{{ }}，安全
const template = `<div>{{ userInput }}</div>`; // Vue会自动转义
