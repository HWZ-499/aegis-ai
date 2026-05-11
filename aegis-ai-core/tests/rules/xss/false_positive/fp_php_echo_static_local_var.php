<?php

// FP: Echoing a local variable whose latest assignment is a static literal is
// not user-controlled output.
$line = "Static status message";
$line = "Static replacement";
echo $line . "<br />";

?>
