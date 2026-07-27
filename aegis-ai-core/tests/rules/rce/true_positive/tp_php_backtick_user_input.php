<?php
// TP: PHP backtick expressions execute a shell command.
$host = $_GET['host'];
$output = `ping -c 1 $host`;
