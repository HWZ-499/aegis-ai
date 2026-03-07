<?php
// TP: 用户可控的 cmd 直接传入 system()，存在命令执行风险。
$cmd = $_GET['cmd'] ?? 'id';
system($cmd);
