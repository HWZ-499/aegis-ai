<?php
/**
 * TP: unserialize 使用 $_GET 输入，存在反序列化风险。
 * 期望检测: DESERIALIZATION (High)
 */
$data = $_GET['data'];
$obj = unserialize($data);
