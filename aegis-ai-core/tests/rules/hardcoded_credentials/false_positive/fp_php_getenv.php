<?php
/**
 * FP: 使用 getenv 读取凭证，非硬编码，不应报硬编码凭证。
 * 期望: 无 HARDCODED_CREDENTIALS
 */
$api_key = getenv("API_KEY");
