/**
 * XSS假漏洞测试用例（应该不报告）
 * 
 * 场景：硬编码字符串输出到HTML，不包含用户输入
 * 预期：不应该报告漏洞
 */

// 假漏洞：硬编码字符串，安全
document.getElementById('content').innerHTML = "Hello World";

// 假漏洞：硬编码HTML，安全
document.getElementById('content').innerHTML = "<div>Welcome</div>";

// 假漏洞：常量字符串，安全
const safeHtml = "<div>Safe content</div>";
document.getElementById('content').innerHTML = safeHtml;

// 假漏洞：硬编码字符串拼接，安全
const header = "<h1>";
const footer = "</h1>";
document.getElementById('content').innerHTML = header + "Title" + footer;

// 假漏洞：Angular硬编码字符串，安全
import { DomSanitizer } from '@angular/platform-browser';
const sanitizer = new DomSanitizer();
const safeHtml2 = sanitizer.bypassSecurityTrustHtml("<div>Safe</div>");

// 假漏洞：React硬编码字符串，安全
const element = <div dangerouslySetInnerHTML={{ __html: "<div>Safe</div>" }} />;
