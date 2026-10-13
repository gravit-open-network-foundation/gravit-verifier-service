<?php
// Gravit Verifier hosted API: storage, keys, receipts. Lives outside the web root.
declare(strict_types=1);

const GV_SERVICE = 'gravitverifier.space';
const GV_PLANS = ['free' => 1000, 'pro' => 100000, 'enterprise' => 10000000];   // verifications per calendar month (UTC)
const GV_MAX_BODY = 1048576;                                                   // 1 MiB

function gv_dir(): string { return getenv('GV_PRIVATE') ?: __DIR__; }
function gv_python(): string { return getenv('GV_PYTHON') ?: '/usr/local/bin/python3.12'; }

function gv_db(): PDO {
    static $db = null;
    if ($db) { return $db; }
    $db = new PDO('sqlite:' . gv_dir() . '/data/service.sqlite', null, null,
                  [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]);
    $db->exec('PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;');
    $db->exec('CREATE TABLE IF NOT EXISTS accounts (id INTEGER PRIMARY KEY, public_id TEXT UNIQUE NOT NULL, email TEXT NOT NULL,
                 plan TEXT NOT NULL, partner TEXT, created TEXT NOT NULL, plan_until TEXT, active INTEGER NOT NULL DEFAULT 1)');
    $db->exec('CREATE TABLE IF NOT EXISTS api_keys (hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id),
                 prefix TEXT NOT NULL, created TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0)');
    $db->exec('CREATE TABLE IF NOT EXISTS entries (account_id INTEGER NOT NULL REFERENCES accounts(id), seq INTEGER NOT NULL,
                 created TEXT NOT NULL, decision_id TEXT NOT NULL, artifact_id TEXT NOT NULL, state TEXT, status TEXT NOT NULL,
                 receipt TEXT NOT NULL, signature TEXT NOT NULL, entry_hash TEXT NOT NULL, result TEXT NOT NULL,
                 PRIMARY KEY (account_id, seq))');
    @chmod(gv_dir() . '/data/service.sqlite', 0600);
    return $db;
}

/** Canonical JSON: sorted keys, no whitespace, unescaped slashes and Unicode (same as Python's
 *  json.dumps(sort_keys=True, separators=(",", ":"), ensure_ascii=False) for strings and integers). */
function gv_canon($v): string {
    if (is_array($v)) {
        if (array_is_list($v)) { return '[' . implode(',', array_map('gv_canon', $v)) . ']'; }
        ksort($v, SORT_STRING);
        $parts = [];
        foreach ($v as $k => $x) { $parts[] = json_encode((string)$k, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . ':' . gv_canon($x); }
        return '{' . implode(',', $parts) . '}';
    }
    return json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

function gv_service_key(): array {
    $f = gv_dir() . '/data/service.key';
    if (!file_exists($f)) {
        $kp = sodium_crypto_sign_keypair();
        file_put_contents($f, base64_encode($kp), LOCK_EX);
        chmod($f, 0600);
    }
    $kp = base64_decode(trim(file_get_contents($f)));
    $pk = sodium_crypto_sign_publickey($kp);
    return ['sk' => sodium_crypto_sign_secretkey($kp), 'pk' => $pk, 'key_id' => substr(hash('sha256', $pk), 0, 16)];
}

function gv_public_key_doc(): array {
    $k = gv_service_key();
    return ['service' => GV_SERVICE, 'algorithm' => 'Ed25519', 'key_id' => $k['key_id'],
            'public_key' => base64_encode($k['pk']),
            'note' => 'Signs receipts of the hosted Gravit Verifier. Receipts are hash-chained per account; verify offline with the SDK.'];
}

function gv_new_id(string $prefix, int $bytes = 16): string { return $prefix . bin2hex(random_bytes($bytes)); }
function gv_now(): string { return gmdate('Y-m-d\TH:i:s\Z'); }

function gv_create_account(string $email, string $plan, ?string $partner = null, ?string $until = null): array {
    if (!isset(GV_PLANS[$plan])) { throw new InvalidArgumentException("unknown plan $plan"); }
    $pub = gv_new_id('acct_', 8);
    gv_db()->prepare('INSERT INTO accounts (public_id, email, plan, partner, created, plan_until) VALUES (?,?,?,?,?,?)')
        ->execute([$pub, strtolower($email), $plan, $partner, gv_now(), $until]);
    return ['id' => (int)gv_db()->lastInsertId(), 'public_id' => $pub];
}

function gv_create_key(int $accountId): string {
    $key = gv_new_id('gv_', 24);
    gv_db()->prepare('INSERT INTO api_keys (hash, account_id, prefix, created) VALUES (?,?,?,?)')
        ->execute([hash('sha256', $key), $accountId, substr($key, 0, 9), gv_now()]);
    return $key;
}

function gv_account_for_key(?string $key): ?array {
    if (!$key || !preg_match('/^gv_[0-9a-f]{48}$/', $key)) { return null; }
    $st = gv_db()->prepare('SELECT a.* FROM api_keys k JOIN accounts a ON a.id = k.account_id
                            WHERE k.hash = ? AND k.revoked = 0 AND a.active = 1');
    $st->execute([hash('sha256', $key)]);
    $a = $st->fetch();
    if (!$a) { return null; }
    if ($a['plan'] !== 'free' && $a['plan_until'] && $a['plan_until'] < gv_now()) { $a['plan'] = 'free'; }  // expired paid or partner plan
    return $a;
}

function gv_usage(array $acct): array {
    $month = gmdate('Y-m');
    $st = gv_db()->prepare("SELECT COUNT(*) FROM entries WHERE account_id = ? AND substr(created, 1, 7) = ?");
    $st->execute([$acct['id'], $month]);
    return ['plan' => $acct['plan'], 'plan_until' => $acct['plan_until'], 'month' => $month,
            'used' => (int)$st->fetchColumn(), 'limit' => GV_PLANS[$acct['plan']]];
}

/** Run the Python worker on the raw request body (passed unchanged, so signed numbers keep their exact form).
 *  Returns [meta array, raw canonical result JSON] or throws. */
function gv_run_worker(string $body): array {
    $p = proc_open([gv_python(), gv_dir() . '/worker.py'], [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes,
                   null, ['PATH' => '/usr/local/bin:/usr/bin:/bin', 'HOME' => getenv('HOME') ?: '/tmp', 'PYTHONDONTWRITEBYTECODE' => '1']);
    if (!is_resource($p)) { throw new RuntimeException('worker could not start'); }
    fwrite($pipes[0], $body);
    fclose($pipes[0]);
    $out = stream_get_contents($pipes[1]); $err = stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $rc = proc_close($p);
    $lines = explode("\n", trim((string)$out), 2);
    $meta = json_decode($lines[0] ?? '', true);
    if ($rc !== 0 || !is_array($meta)) { error_log("gravit worker rc=$rc err=" . substr($err, 0, 500)); throw new RuntimeException('worker failed'); }
    return [$meta, $lines[1] ?? ''];
}

/** Append a signed, hash-chained receipt for this account. Returns [receipt, signature, entry_hash]. */
function gv_record(array $acct, array $meta, string $result): array {
    $db = gv_db();
    $db->beginTransaction();
    try {
        $last = $db->prepare('SELECT seq, entry_hash FROM entries WHERE account_id = ? ORDER BY seq DESC LIMIT 1');
        $last->execute([$acct['id']]);
        $prev = $last->fetch() ?: ['seq' => 0, 'entry_hash' => str_repeat('0', 64)];
        $k = gv_service_key();
        $receipt = [
            'format' => 'gravit-verifier-receipt-1', 'service' => GV_SERVICE, 'service_key_id' => $k['key_id'],
            'account' => $acct['public_id'], 'seq' => (int)$prev['seq'] + 1, 'issued_at' => gv_now(),
            'verifier_version' => $meta['verifier_version'], 'artifact_id' => $meta['artifact_id'],
            'decision_id' => $meta['decision_id'], 'final_epistemic_state' => $meta['state'], 'status' => $meta['status'],
            'request_sha256' => $meta['request_sha256'], 'result_sha256' => hash('sha256', $result),
            'prev_entry_hash' => $prev['entry_hash'],
        ];
        $canon = gv_canon($receipt);
        $sig = base64_encode(sodium_crypto_sign_detached($canon, $k['sk']));
        $hash = hash('sha256', $canon);
        $db->prepare('INSERT INTO entries VALUES (?,?,?,?,?,?,?,?,?,?,?)')->execute([
            $acct['id'], $receipt['seq'], $receipt['issued_at'], $meta['decision_id'], $meta['artifact_id'], $meta['state'],
            $meta['status'], $canon, $sig, $hash, $result]);
        $db->commit();
        return [$receipt, $sig, $hash];
    } catch (Throwable $e) { $db->rollBack(); throw $e; }
}
