/**
 * FP: 在同一测试块里混合 req.params 与 request(server) 时，
 * supertest 本地调用不应被判定为 SSRF。
 * 期望: 无 SSRF
 */
function suite(createApp) {
  it("should exercise local app", function (done) {
    var server = createApp();
    server.get("*", function (req, res) {
      res.end(req.params[0]);
    });

    request(server)
      .get("/user/tobi.json")
      .expect("/user/tobi.json", done);
  });
}
