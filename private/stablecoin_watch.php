<?php
// Cron: settle stablecoin and TON orders. Every 5 minutes: php ~/verifier-service/stablecoin_watch.php >> ~/verifier-service/data/stablecoin.out
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
require __DIR__ . '/lib.php';
require __DIR__ . '/stablecoin.php';
require __DIR__ . '/ton.php';

$lock = fopen(gv_dir() . '/data/stablecoin.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) { exit(0); }   // the previous run is still busy
try {
    foreach (gv_sc_watch() as $line) { echo gv_now(), ' ', $line, "\n"; }
    foreach (gv_ton_watch() as $line) { echo gv_now(), ' ', $line, "\n"; }
} catch (Throwable $e) {
    echo gv_now(), ' error: ', $e->getMessage(), "\n";
    exit(1);
}
