<?php
/**
 * PHP XSS 合成测试用例
 * TP（直接 echo 用户输入）/ TN（htmlspecialchars 净化）/ 传播污点
 */

// ── TP-1: echo 直接输出 GET 参数 ──────────────────────────────
// EXPECT: XSS_RISK, line 10
$name = $_GET['name'];
echo $name;


// ── TP-2: print 输出 POST 参数 ───────────────────────────────
// EXPECT: XSS_RISK, line 16
$msg = $_POST['message'];
print "<p>" . $msg . "</p>";


// ── TP-3: echo 直接输出超全局变量（无中间变量）───────────────────
// EXPECT: XSS_RISK, line 21
echo $_REQUEST['comment'];


// ── TN-1: htmlspecialchars 净化 ──────────────────────────────
// EXPECT: no XSS finding
$name = $_GET['name'];
$safe = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
echo $safe;


// ── TN-2: htmlentities 净化 ──────────────────────────────────
// EXPECT: no XSS finding
$input = $_POST['input'];
$safe = htmlentities($input);
echo $safe;


// ── TN-3: strip_tags 净化 ────────────────────────────────────
// EXPECT: no XSS finding (strip_tags 去除 HTML 标签)
$comment = $_GET['comment'];
$clean = strip_tags($comment);
echo $clean;


// ── PROP-1: 赋值传播后 echo ──────────────────────────────────
// EXPECT: XSS_RISK, line 46
$raw = $_GET['q'];
$val = $raw;
echo "<div>" . $val . "</div>";


// ── PROP-2: 字符串拼接传播 ───────────────────────────────────
// EXPECT: XSS_RISK, line 53
$user = $_GET['user'];
$greeting = "Hello " . $user;
echo $greeting;
?>
