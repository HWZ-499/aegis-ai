<?php
/**
 * TP: allowed_classes=true does not restrict object instantiation.
 * Expected: DESERIALIZATION
 */
$data = $_POST['payload'];
$obj = unserialize($data, ['allowed_classes' => true]);
