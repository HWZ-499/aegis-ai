<?php

/**
 * TP: copy/rename destination paths can be user controlled.
 * Expected: PATH_TRAVERSAL
 */
copy('/srv/uploads/report.txt', $_GET['dest']);
rename('/srv/uploads/old.txt', $_POST['new_name']);
