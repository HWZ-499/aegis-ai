/**
 * SQL注入假漏洞测试用例（应该不报告）
 * 
 * 场景：使用参数化查询（prepare()），安全
 * 预期：不应该报告漏洞
 */

import { query } from 'mysql';

// 从HTTP请求获取用户输入
const userId = req.query.id;

// 假漏洞：参数化查询，安全
const sql = "SELECT * FROM users WHERE id = ?";
query(sql, [userId]);

// 假漏洞：PDO prepare()，安全
const stmt = db.prepare("SELECT * FROM users WHERE id = :id");
stmt.execute({ id: userId });

// 假漏洞：Sequelize参数化查询，安全
import { User } from './models';
User.find({ where: { id: userId } }); // 没有字符串拼接，安全

// 假漏洞：Mongoose参数化查询，安全
import mongoose from 'mongoose';
mongoose.model('User').find({ email: req.body.email }); // 没有字符串拼接，安全
