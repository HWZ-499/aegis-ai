<?php

/**
 * FP: 使用常量作为 MongoDB 查询条件，不应视为 NoSQL 注入。
 * 期望: 无 NOSQL_INJECTION
 */
function findUserSafe($collection) {
    $collection->find(['user' => 'admin']);
}

