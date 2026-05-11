<?php

$name = $_GET["name"] ?? "";
$clean = preg_replace('/<(.*)script/i', '', $name);

echo htmlspecialchars($clean, ENT_QUOTES, 'UTF-8');
