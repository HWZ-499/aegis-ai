<?php

$page = <<<HTML
<script>
  const next = document.location.href.substring(document.location.href.indexOf("next=") + 5);
  document.write("<option>" + next + "</option>");
</script>
HTML;
