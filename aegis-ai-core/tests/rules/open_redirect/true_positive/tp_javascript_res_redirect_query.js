// TP: 用户可控的 query 参数直接用于 res.redirect，存在开放重定向风险。
function handlerTP(req, res) {
  const url = req.query.next || "/";
  res.redirect(url);
}
