<?php
// FP: Fixed trusted service endpoint.
$handle = curl_init('https://api.example.com/health');
curl_exec($handle);
