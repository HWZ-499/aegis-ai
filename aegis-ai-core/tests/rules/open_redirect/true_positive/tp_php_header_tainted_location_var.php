<?php

// TP: header argument is a tainted variable that contains a Location header.
function redirect_var_tp(): void {
    $target = $_GET['next'] ?? '/';
    $header = 'Location: ' . $target;
    header($header);
}
