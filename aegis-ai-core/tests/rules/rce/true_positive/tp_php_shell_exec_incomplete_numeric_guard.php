<?php

$target = $_REQUEST['ip'];
$octet = explode('.', $target);

if (is_numeric($octet[0])) {
    shell_exec('ping -c 4 ' . $target);
}
