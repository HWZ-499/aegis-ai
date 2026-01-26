// index.js - Aegis-AI 后端核心 (国产之光 DeepSeek 版)
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios'); // 依然用最稳的 Axios，但不需要代理了！

const app = express();
app.use(cors());
app.use(express.json());

const SYSTEM_PROMPT = `你是一个Web安全专家。分析代码中的漏洞。
只输出合法的JSON数组格式，绝不包含其他废话。
格式：[{"vuln_name":"...","severity":"...","cwe_id":"...","description":"...","fix_code":"..."}]
如果没漏洞，输出 []。`;

// 核心扫描接口
app.post('/api/scan', async (req, res) => {
    const { code } = req.body;
    if (!code) return res.status(400).json({ error: '没有提供代码' });

    try {
        console.log("🚀 正在呼叫 DeepSeek 审计引擎...");
        
        // 直连 DeepSeek 官方接口，完全不用代理！
        const result = await axios.post('https://api.deepseek.com/chat/completions', {
            model: "deepseek-chat",
            messages: [
                { role: "system", content: SYSTEM_PROMPT },
                { role: "user", content: `待分析代码:\n${code}` }
            ]
        }, {
            headers: { 'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}` }
        });

        // 解析返回的 JSON
        let aiResponse = result.data.choices[0].message.content;
        aiResponse = aiResponse.replace(/```json/g, '').replace(/```/g, '').trim();
        
        console.log("✅ 审计完成！");
        res.json(JSON.parse(aiResponse)); 
    } catch (error) {
        console.error("❌ 报错信息:", error.response ? error.response.data : error.message);
        res.status(500).json({ error: 'AI 分析失败' });
    }
});

const PORT = 3000;
app.listen(PORT, () => console.log(`🛡️ Aegis-AI (DeepSeek版) 已启动! 端口: ${PORT}`));