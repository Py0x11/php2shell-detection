<?php
header('X-Lab: php2shell');
echo "php2shell-lab php=" . PHP_VERSION . " sapi=" . PHP_SAPI . "\n";
echo "session.upload_progress.enabled=" . ini_get('session.upload_progress.enabled') . "\n";
echo "memory_limit=" . ini_get('memory_limit') . " post_max_size=" . ini_get('post_max_size') . "\n";
