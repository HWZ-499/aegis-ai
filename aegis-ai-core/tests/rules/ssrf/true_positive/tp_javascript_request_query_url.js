/**
 * TP: 用户输入直接流入 request(url)。
 * 期望: 检测到 SSRF
 */
function handler(req) {
  const url = req.query.url;
  return request(url);
}
