<?php
// TP: User-controlled URL is fetched by the server.
$url = $_GET['url'];
$body = file_get_contents($url);
