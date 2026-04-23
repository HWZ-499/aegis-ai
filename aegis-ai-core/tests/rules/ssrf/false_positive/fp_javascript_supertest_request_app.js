/**
 * FP: supertest/request(app) 属于本地应用测试，不是外部 URL 请求。
 * 期望: 无 SSRF
 */
function runTest(req) {
  const app = createApp(req.query.url);
  return request(app)
    .get("/")
    .expect(200);
}
