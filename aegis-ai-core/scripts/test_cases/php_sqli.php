<?php
/**
 * PHP SQL 注入合成测试用例
 * TP（直接注入）/ TN（参数化查询或强类型净化）/ 传播污点
 */

// ── TP-1: 直接字符串拼接 mysql_query ──────────────────────────
// EXPECT: SQL_INJECTION, line 11
$id = $_GET['id'];
mysql_query("SELECT * FROM users WHERE id = " . $id);


// ── TP-2: PDO 对象 query()，无绑定 ──────────────────────────
// EXPECT: SQL_INJECTION, line 17
$name = $_POST['name'];
$pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");


// ── TP-3: $db->execute() 直接拼接 ───────────────────────────
// EXPECT: SQL_INJECTION, line 23
$email = $_REQUEST['email'];
$stmt = "UPDATE users SET email = '" . $email . "'";
$db->execute($stmt);


// ── TN-1: 参数化查询 PDO（安全）──────────────────────────────
// EXPECT: no SQL_INJECTION finding
$id = $_GET['id'];
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$id]);


// ── TN-2: intval 强类型净化 ──────────────────────────────────
// EXPECT: no SQL_INJECTION finding
$id = intval($_GET['id']);
mysql_query("SELECT * FROM users WHERE id = " . $id);


// ── TN-3: mysqli_real_escape_string ──────────────────────────
// EXPECT: no SQL_INJECTION (sanitized path, Low降级后被跳过)
$name = mysqli_real_escape_string($conn, $_GET['name']);
$pdo->query("SELECT * FROM users WHERE name = '" . $name . "'");


// ── PROP-1: 多跳变量传播 ──────────────────────────────────────
// EXPECT: SQL_INJECTION, line 48
$raw = $_GET['q'];
$term = $raw;
$search = $term;
mysql_query("SELECT * FROM items WHERE name LIKE '%" . $search . "%'");


// ── PROP-2: 条件守护后赋值（模拟 impossible.php 风格）────────────
// EXPECT: no SQL_INJECTION (guard 守护，变量视为 sanitized)
$id = $_GET['id'];
if (is_numeric($id)) {
    $safe_id = $id;
    mysql_query("SELECT * FROM users WHERE id = " . $safe_id);
}
?>
