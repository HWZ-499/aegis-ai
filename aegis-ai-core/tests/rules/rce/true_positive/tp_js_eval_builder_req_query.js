function buildCode(input) {
  return "run(" + input + ")";
}

eval(buildCode(req.query.cmd));
