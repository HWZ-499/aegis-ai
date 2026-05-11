<?php

/**
 * TP: updateOne 的更新文档来自用户输入，即使过滤条件是常量也存在 NoSQL 注入风险。
 * 期望检测: NOSQL_INJECTION (High)
 */
function updateProfile($collection) {
    $collection->updateOne(['role' => 'user'], ['$set' => $_POST['profile']]);
}
