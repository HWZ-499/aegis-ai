<?php
// FP: The complete user-controlled argument is shell-escaped before execution.
$host = $_GET['host'];
system('ping -c 1 ' . escapeshellarg($host));
