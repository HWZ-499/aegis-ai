<?php
// TP: CURLOPT_URL is configured from user input.
$handle = curl_init();
curl_setopt($handle, CURLOPT_URL, $_POST['target']);
curl_exec($handle);
