const needle = require("needle");

function renderResearch(req, res) {
  const url = req.query.url;
  needle.get(url, (error, upstreamResponse, body) => {
    if (!error && upstreamResponse.statusCode === 200) {
      res.write(body);
    }
  });
}
