<?php

// FP: A static query result echoed from a local DB cursor is not direct user
// input. Stored XSS needs a different rule than reflected output taint.
$query = "SELECT * FROM users";
$result = mssql_query($query);

while ($record = mssql_fetch_array($result)) {
    echo $record["first_name"] . " " . $record["last_name"] . "<br />";
}

?>
