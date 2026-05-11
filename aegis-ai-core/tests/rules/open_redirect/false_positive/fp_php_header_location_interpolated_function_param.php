<?php

// FP: generic redirect helper parameter is not a local user-input source.
function redirect_helper(string $location): void {
    header("Location: {$location}");
}
