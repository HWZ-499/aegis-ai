const yaml = require("js-yaml");

const document = req.body.payload;
yaml.load(document);
