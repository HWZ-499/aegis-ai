<?php
// TP: 用户可控的 name 直接 echo 输出，存在 XSS 风险。
$name = $_GET['name'] ?? '';
echo $name;
