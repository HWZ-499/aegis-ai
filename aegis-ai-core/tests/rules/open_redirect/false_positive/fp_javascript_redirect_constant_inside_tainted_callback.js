// FP: 请求输入被传给认证函数，但回调中的跳转目标为常量，不是用户可控 URL。
function handlerFP(req, res, userDAO) {
  const { userName, password } = req.body;
  userDAO.validateLogin(userName, password, (err, user) => {
    if (err) {
      return res.redirect("/login");
    }
    return res.redirect(user.isAdmin ? "/benefits" : "/dashboard");
  });
}
