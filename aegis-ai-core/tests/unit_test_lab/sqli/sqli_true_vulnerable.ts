/**
 * SQL注入真漏洞测试用例
 * 
 * 场景：用户输入直接拼接到SQL查询中
 * 预期：应该报告 SQL_INJECTION (High)
 */

import { query } from 'mysql';

// 从HTTP请求获取用户输入
const userId = req.query.id;

// 真漏洞：字符串拼接SQL查询
const sql = "SELECT * FROM users WHERE id = " + userId;
query(sql);

// 真漏洞：模板字符串注入
const sql2 = `SELECT * FROM users WHERE email = '${req.body.email}'`;
query(sql2);

// 真漏洞：Sequelize ORM字符串拼接
import { User } from './models';
User.find({ where: { email: req.body.email + "' OR '1'='1" } });

// 真漏洞：Mongoose字符串拼接
import mongoose from 'mongoose';
mongoose.model('User').find({ email: req.body.email + "' OR '1'='1" });
