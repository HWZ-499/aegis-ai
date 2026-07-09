const needle = require("needle");

function cacheResearch(url, file) {
  needle.get(url, (error, upstreamResponse, body) => {
    if (!error && upstreamResponse.statusCode === 200) {
      file.write(body);
    }
  });
}
