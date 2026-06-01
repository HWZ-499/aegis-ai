const express = require("express");

const app = express();

app.get("/users/:id", async (req, res) => {
  const id = req.params.id;
  const sql = "SELECT * FROM users WHERE id = " + id;
  const rows = await req.db.query(sql);
  res.json(rows);
});

app.get("/profile", (req, res) => {
  res.send("<h1>Welcome " + req.query.name + "</h1>");
});

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  const response = await fetch(target);
  res.send(await response.text());
});

module.exports = app;
