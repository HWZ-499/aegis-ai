<?php
// FP: The else branch only runs after user_id matches digits, so $id cannot
// inject SQL syntax even though it is interpolated into the query string.
if (isset($_GET['user_id'])) {
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        echo "Invalid user ID";
    } else {
        $id = $_GET['user_id'];
        $query = "SELECT user_id FROM users WHERE user_id = '$id'";
        mysqli_query($GLOBALS["___mysqli_ston"], $query);
    }
}

