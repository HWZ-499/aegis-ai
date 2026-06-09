<?php
// TP: The invalid branch does not exit and there is no else branch, so the
// later SQL query is still reachable with the original user-controlled value.
if (isset($_GET['user_id'])) {
    if (!preg_match('/^\d+$/', $_GET['user_id'])) {
        echo "Invalid user ID";
    }

    $id = $_GET['user_id'];
    $query = "SELECT user_id FROM users WHERE user_id = '$id'";
    mysqli_query($GLOBALS["___mysqli_ston"], $query);
}

