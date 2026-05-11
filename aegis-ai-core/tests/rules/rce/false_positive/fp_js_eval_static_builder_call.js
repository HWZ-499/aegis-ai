function buildBundle(name) {
  return "console.log(" + JSON.stringify(name) + ")";
}

eval(buildBundle("status"));
