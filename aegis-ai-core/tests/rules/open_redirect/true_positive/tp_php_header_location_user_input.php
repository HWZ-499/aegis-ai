<?php

// TP: 用户可控的 next 参数直接用于构造 Location 头，存在开放重定向风险。
function redirect_tp(): void {
    $next = $_GET['next'] ?? '/';
    header("Location: " . $next);
}

