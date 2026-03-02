/**
 * FP: 从环境变量读取密钥 — 安全做法，不应检测为漏洞。
 * 期望: 无 HARDCODED_CREDENTIALS
 */
const apiKey = process.env.API_KEY;
const dbPassword = process.env.DB_PASSWORD;
