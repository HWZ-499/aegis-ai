<?php

// FP: 重定向目标为常量路径，不受用户输入控制。
function redirect_fp(): void {
    $next = '/dashboard';
    header("Location: " . $next);
}

