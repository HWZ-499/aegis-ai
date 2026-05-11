<?php

// FP: The uploaded name only feeds a randomized basename, and the extension is
// constrained before the generated filename reaches rename().
$uploaded_name = $_FILES['uploaded']['name'];
$uploaded_ext = substr($uploaded_name, strrpos($uploaded_name, '.') + 1);
$uploaded_tmp = $_FILES['uploaded']['tmp_name'];
$target_path = '/var/www/uploads/';
$target_file = md5(uniqid() . $uploaded_name) . '.' . $uploaded_ext;

if (strtolower($uploaded_ext) == 'jpg' || strtolower($uploaded_ext) == 'jpeg' || strtolower($uploaded_ext) == 'png') {
    rename($uploaded_tmp, $target_path . $target_file);
}

?>
