// Test file with intentional vulnerabilities for Aegis AI testing
const express = require('express');
const mysql = require('mysql');
const app = express();

app.get('/user', (req, res) => {
    const userId = req.query.id;
    
    // SQL Injection - string concatenation
    const query = "SELECT * FROM users WHERE id = '" + userId + "'";
    mysql.query(query, (err, results) => {
        res.json(results);
    });
    
    // XSS - direct user input in response
    res.send("<h1>Welcome " + req.query.name + "</h1>");
    
    // RCE - eval with user input
    eval(req.body.code);
    
    // Path Traversal
    const fs = require('fs');
    const filePath = req.query.file;
    fs.readFile(filePath, (err, data) => {
        res.send(data);
    });
});

// Hardcoded credentials
const password = "SuperSecret123!";
const apiKey = "sk-1234567890abcdef";

module.exports = app;
