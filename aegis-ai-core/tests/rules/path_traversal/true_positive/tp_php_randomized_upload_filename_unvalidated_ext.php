<?php

// TP: A randomized basename is not enough if the extension/path suffix remains
// attacker-controlled and unvalidated.
$uploaded_name = $_FILES['uploaded']['name'];
$uploaded_ext = substr($uploaded_name, strrpos($uploaded_name, '.') + 1);
$uploaded_tmp = $_FILES['uploaded']['tmp_name'];
$target_path = '/var/www/uploads/';
$target_file = md5(uniqid() . $uploaded_name) . '.' . $uploaded_ext;

rename($uploaded_tmp, $target_path . $target_file);

?>
