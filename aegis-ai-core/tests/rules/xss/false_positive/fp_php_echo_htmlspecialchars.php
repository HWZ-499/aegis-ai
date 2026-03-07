<?php
// FP: 输出前经 htmlspecialchars 转义，无 XSS 风险。
$name = $_GET['name'] ?? '';
echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
