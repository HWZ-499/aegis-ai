<?php
/**
 * FP: 使用 basename() 净化路径后再读文件，不应报路径遍历。
 * 期望: 无 PATH_TRAVERSAL
 */
$name = $_GET['file'];
$safe = basename($name);
readfile('/var/www/uploads/' . $safe);
