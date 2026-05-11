<?php

// FP: This PHP template emits static client-side JavaScript. The regex
// supplement should not treat JS variables inside the PHP string as PHP XSS.
$html .= "
<script>
function renderUser(user_json) {
    var user_info = document.getElementById('user_info');
    user_info.innerHTML = 'User details: ' + user_json.name;
}
</script>
";

?>
