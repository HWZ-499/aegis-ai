<?php

/**
 * TP: 使用 $_GET 直接作为 MongoDB 查询条件，存在 NoSQL 注入风险。
 * 期望检测: NOSQL_INJECTION (High)
 */
function findUser($collection) {
    $collection->find(['user' => $_GET['user']]);
}

