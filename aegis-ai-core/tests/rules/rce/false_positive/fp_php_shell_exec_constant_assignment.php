<?php
// FP: shell_exec 参数为常量命令，即使赋值给变量也不应报 RCE。
$out = shell_exec("php -v");
