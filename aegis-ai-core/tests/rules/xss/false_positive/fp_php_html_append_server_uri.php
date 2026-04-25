<?php

$request_url = $_SERVER['REQUEST_URI'];
$html = '';
$html .= "<script>const current = '{$request_url}';</script>";
