<?php
/**
 * FP: unserialize 使用 allowed_classes 限制，本规则通过 _extra_filter 跳过。
 * 期望: 无 DESERIALIZATION（或 Low）
 */
$data = $_GET['data'];
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
