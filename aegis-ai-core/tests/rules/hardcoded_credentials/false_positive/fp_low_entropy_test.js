/**
 * FP: 低熵短字符串（测试账号），不应报 Critical。
 * 期望: 无 HARDCODED_CREDENTIALS（因为值太短/低熵，_is_placeholder 过滤）
 */
const testUser = { username: "admin", password: "admin" };
