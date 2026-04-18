/**
 * FP: 函数名包含 request 子串，不应被识别为 SSRF sink。
 * 期望: 无 SSRF
 */
function handle_request(url) {
  return url;
}

function process(req, res) {
  const target = req.query.url;
  const value = handle_request(target);
  res.send(value);
}
