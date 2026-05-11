<?php

// TP: user-controlled redirect target is interpolated into a Location header.
function redirect_interpolated_tp(): void {
    $location = $_GET['next'] ?? '/';
    header("Location: {$location}");
}
