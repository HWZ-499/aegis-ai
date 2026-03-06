<?php
/**
 * PHP RCE / 命令执行合成测试用例
 * TP（直接命令执行）/ TN（净化或白名单）/ 传播污点
 */

// ── TP-1: shell_exec 直接注入 ────────────────────────────────
// EXPECT: RCE_COMMAND_EXEC, line 10
$host = $_GET['host'];
$output = shell_exec("ping -c 1 " . $host);


// ── TP-2: exec() 用户输入 ────────────────────────────────────
// EXPECT: RCE_COMMAND_EXEC, line 16
$cmd = $_POST['cmd'];
exec($cmd);


// ── TP-3: system() 用户输入 ──────────────────────────────────
// EXPECT: RCE_COMMAND_EXEC, line 22
$target = $_REQUEST['ip'];
system("traceroute " . $target);


// ── TN-1: intval 净化（整数化后命令注入不可能）────────────────
// EXPECT: no RCE finding
$port = intval($_GET['port']);
shell_exec("nc localhost " . $port);


// ── TN-2: 白名单验证（守护后跳过）───────────────────────────
// EXPECT: no RCE finding (is_numeric 守护)
$id = $_GET['id'];
if (is_numeric($id)) {
    $safe = $id;
    shell_exec("process_id " . $safe);
}


// ── TN-3: stripslashes + is_numeric 守护 ─────────────────────
// EXPECT: no RCE finding (impossible.php 风格)
$target = $_REQUEST['ip'];
$target = stripslashes($target);
$octet = explode(".", $target);
if (is_numeric($octet[0]) && is_numeric($octet[1])) {
    $target = $octet[0] . "." . $octet[1];
    $cmd = shell_exec("ping " . $target);
}


// ── PROP-1: 变量传播后执行 ──────────────────────────────────
// EXPECT: RCE_COMMAND_EXEC, line 51
$raw = $_GET['arg'];
$param = $raw;
$cmd = "ls " . $param;
$output = shell_exec($cmd);


// ── PROP-2: passthru 执行 ────────────────────────────────────
// EXPECT: RCE_COMMAND_EXEC, line 58
$script = $_POST['script'];
passthru("/bin/bash " . $script);
?>
