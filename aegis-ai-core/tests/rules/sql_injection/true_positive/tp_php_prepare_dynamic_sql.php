<?php

// TP: prepare() does not protect dynamic table or column fragments.
$table = $_GET['table'] ?? 'users';
$id = $_GET['id'] ?? '1';
$pdo = new PDO('sqlite::memory:');
$stmt = $pdo->prepare('SELECT * FROM ' . $table . ' WHERE id = ?');
$stmt->execute([$id]);
