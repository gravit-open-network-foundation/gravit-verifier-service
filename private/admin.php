<?php
// Admin CLI for the hosted API (run on the server). Usage:
//   php admin.php account <email> <free|pro|enterprise> [partner] [until YYYY-MM-DD]   -> creates account and first key
//   php admin.php key <account_public_id>                                                -> new API key
//   php admin.php revoke <key_prefix>                                                   -> revoke keys with this prefix
//   php admin.php list
//   php admin.php delete <email>                                                        -> erase personal data (GDPR); receipts stay in the public log
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { exit(1); }
require (getenv('GV_PRIVATE') ?: __DIR__) . '/lib.php';
$cmd = $argv[1] ?? '';
if ($cmd === 'account') {
    $until = isset($argv[5]) ? $argv[5] . 'T23:59:59Z' : null;
    $a = gv_create_account($argv[2], $argv[3], ($argv[4] ?? '') ?: null, $until);
    echo "account {$a['public_id']}\nkey     " . gv_create_key($a['id']) . "\n(the key is shown once; only its hash is stored)\n";
} elseif ($cmd === 'key') {
    $st = gv_db()->prepare('SELECT id FROM accounts WHERE public_id = ?'); $st->execute([$argv[2]]);
    $id = $st->fetchColumn(); if (!$id) { fwrite(STDERR, "no such account\n"); exit(1); }
    echo gv_create_key((int)$id), "\n";
} elseif ($cmd === 'revoke') {
    $st = gv_db()->prepare('UPDATE api_keys SET revoked = 1 WHERE prefix = ?'); $st->execute([$argv[2]]); echo $st->rowCount(), " key(s) revoked\n";
} elseif ($cmd === 'delete') {
    // The receipts are leaves of the public, timestamped receipt log and cannot be removed without
    // breaking every later tree head. They contain no personal data (account id, hashes, states), so
    // erasure removes what identifies the person: the email, the keys and the stored request results.
    $db = gv_db(); $st = $db->prepare('SELECT id, public_id FROM accounts WHERE email = ?'); $st->execute([strtolower($argv[2] ?? '')]);
    $n = 0;
    foreach ($st->fetchAll() as $a) {
        $db->prepare('DELETE FROM api_keys WHERE account_id = ?')->execute([$a['id']]);
        $db->prepare("UPDATE entries SET result = '{\"erased\":true}' WHERE account_id = ?")->execute([$a['id']]);
        $db->prepare("UPDATE accounts SET email = ?, active = 0 WHERE id = ?")->execute(['erased:' . $a['public_id'], $a['id']]);
        $n++;
    }
    echo "$n account(s) erased; receipts remain in the public log without personal data\n";
} elseif ($cmd === 'list') {
    foreach (gv_db()->query('SELECT a.public_id, a.email, a.plan, a.partner, a.plan_until, a.created,
                (SELECT COUNT(*) FROM entries e WHERE e.account_id = a.id) AS decisions FROM accounts a ORDER BY a.id') as $r) {
        echo implode("\t", array_map('strval', $r)), "\n";
    }
} else { fwrite(STDERR, "usage: see the header of this file\n"); exit(2); }
