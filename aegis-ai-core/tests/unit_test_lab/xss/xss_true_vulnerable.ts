/**
 * XSS真漏洞测试用例
 * 
 * 场景：用户输入直接输出到HTML，未转义
 * 预期：应该报告 XSS_RISK (High)
 */

// 从HTTP请求获取用户输入
const userInput = req.query.comment;

// 真漏洞：用户输入直接输出到innerHTML
document.getElementById('content').innerHTML = userInput;

// 真漏洞：用户输入直接输出到outerHTML
document.getElementById('content').outerHTML = userInput;

// 真漏洞：Angular绕过安全策略
import { DomSanitizer } from '@angular/platform-browser';
const sanitizer = new DomSanitizer();
const safeHtml = sanitizer.bypassSecurityTrustHtml(userInput);

// 真漏洞：React dangerouslySetInnerHTML
const element = <div dangerouslySetInnerHTML={{ __html: userInput }} />;

// 真漏洞：Vue v-html
const template = `<div v-html="${userInput}"></div>`;

// 真漏洞：document.write用户输入
document.write(userInput);
