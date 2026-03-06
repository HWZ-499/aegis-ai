<?php
/**
 * TP: include 使用用户输入作为路径，存在路径遍历风险。
 * 期望检测: PATH_TRAVERSAL (High)
 */
$page = $_GET['page'];
include('/var/www/templates/' . $page);
