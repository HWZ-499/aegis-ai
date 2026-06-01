<?php

$id = $_GET['user_id'];
if (!preg_match('/^\d+$/', $id)) {
    echo 'Invalid user ID';
}

$query = "SELECT * FROM users WHERE user_id = '$id';";
mysqli_query($GLOBALS["___mysqli_ston"], $query);

?>
