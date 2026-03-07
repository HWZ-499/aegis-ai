<?php
// TP: 用户可控的 id 拼接到 SQL 并执行，存在 SQL 注入风险。
$id = $_GET['id'] ?? '1';
$sql = "SELECT * FROM users WHERE id = " . $id;
$conn = new mysqli("localhost", "user", "pass", "db");
$conn->query($sql);
