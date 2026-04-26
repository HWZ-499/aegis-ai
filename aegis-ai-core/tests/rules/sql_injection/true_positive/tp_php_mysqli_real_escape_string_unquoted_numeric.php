<?php
// TP: 仅做 mysqli_real_escape_string 后将变量不加引号拼入 SQL，仍可能注入（数字上下文）。
$id = $_POST['id'];
$id = mysqli_real_escape_string($GLOBALS["___mysqli_ston"], $id);
$query = "SELECT first_name, last_name FROM users WHERE user_id = $id;";
mysqli_query($GLOBALS["___mysqli_ston"], $query);
