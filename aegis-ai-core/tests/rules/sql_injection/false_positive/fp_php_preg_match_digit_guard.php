<?php

if (isset($_GET['user_id'])) {
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        echo 'Invalid user ID';
    } else {
        $id = $_GET['user_id'];
        $query = "SELECT * FROM users WHERE user_id = '$id';";
        mysqli_query($GLOBALS["___mysqli_ston"], $query);
    }
}

?>
