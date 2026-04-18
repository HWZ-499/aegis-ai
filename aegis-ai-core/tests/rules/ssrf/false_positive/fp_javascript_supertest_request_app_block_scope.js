/**
 * FP: 在同一测试代码块中同时出现 req.params 与 request(app)，
 * 当前污点图可能把整个代码块误当成 sink 表达式，导致误报 SSRF。
 * 期望: 无 SSRF
 */
function suite(express) {
  const app = express();

  app.get("*", function (req, res) {
    const echo = req.params[0];
    res.end(echo);

    request(app)
      .get("/user/tobi.json")
      .expect("/user/tobi.json");
  });
}
