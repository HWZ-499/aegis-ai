<?php
// FP: User input is escaped even though it is nested in a concatenation.
echo '<p>' . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . '</p>';
