<?php
// FP: prepare + execute([$id]) 参数化查询，且输入已做类型收敛，不应报 SQL 注入。
$id = (int)($_GET['id'] ?? 0);
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);
