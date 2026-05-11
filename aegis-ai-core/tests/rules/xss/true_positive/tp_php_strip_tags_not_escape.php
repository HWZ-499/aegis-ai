<?php
// TP: strip_tags removes tags but does not perform context-safe HTML escaping.
$comment = $_GET['comment'] ?? '';
echo strip_tags($comment);
