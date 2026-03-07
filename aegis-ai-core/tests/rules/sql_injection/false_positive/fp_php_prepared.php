<?php
// FP: 使用 prepare + bind 参数化查询，无 SQL 注入风险。
$id = $_GET['id'] ?? '1';
$conn = new mysqli("localhost", "user", "pass", "db");
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("s", $id);
$stmt->execute();
