// FP: res.redirect 目标为常量路径，不受用户输入控制。
function handlerFP(req, res) {
  res.redirect("/home");
}
