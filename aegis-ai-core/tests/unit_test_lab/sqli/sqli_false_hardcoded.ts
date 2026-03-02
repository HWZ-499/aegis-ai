/**
 * SQL注入假漏洞测试用例（应该不报告）
 * 
 * 场景：硬编码SQL查询，不包含用户输入
 * 预期：不应该报告漏洞
 */

import { query } from 'mysql';

// 假漏洞：硬编码SQL查询，安全
const sql = "SELECT * FROM users WHERE id = 1";
query(sql);

// 假漏洞：硬编码SQL查询，安全
const sql2 = "SELECT * FROM users WHERE status = 'active'";
query(sql2);

// 假漏洞：常量字符串拼接，安全
const tableName = "users";
const sql3 = "SELECT * FROM " + tableName + " WHERE id = 1";
query(sql3);
