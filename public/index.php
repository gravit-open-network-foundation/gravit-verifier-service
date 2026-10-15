<?php
// Gravit Verifier hosted API v1. Routes: POST /api/v1/verify, GET /api/v1/decisions[/{decision_id}],
// GET /api/v1/export, GET /api/v1/usage, GET /api/v1/service-key, GET /api/v1/status, GET /api/v1/openapi.json,
// POST /api/v1/gate.
declare(strict_types=1);
require (getenv('GV_PRIVATE') ?: dirname(__DIR__, 3) . '/verifier-service') . '/lib.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Gravit-API-Version: 1');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Headers: Authorization, Content-Type');
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(204); exit; }

function out(int $code, $data): void { http_response_code($code); echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT); exit; }
function err(int $code, string $msg): void { out($code, ['error' => $msg]); }

$path = '/' . trim(preg_replace('#^.*/api#', '', parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH)), '/');
$method = $_SERVER['REQUEST_METHOD'];

if ($path === '/v1/service-key' && $method === 'GET') { out(200, gv_public_key_doc()); }
if ($path === '/v1/openapi.json' && $method === 'GET') { readfile(__DIR__ . '/openapi.json'); exit; }
if ($path === '/v1/status' && $method === 'GET') {
    try { [$meta] = gv_run_worker('{"status":true}'); } catch (Throwable $e) { out(503, ['status' => 'degraded', 'error' => 'verifier unavailable']); }
    out(200, ['status' => 'ok', 'api' => 'v1', 'time' => gv_now(), 'service_key_id' => gv_public_key_doc()['key_id'] ?? null,
              'verifier_version' => $meta['verifier_version'] ?? null, 'graviteron' => $meta['graviteron'] ?? null,
              'capability_gate' => $meta['capability_gate'] ?? null]);
}
if ($path === '/v1' || $path === '/') { out(200, ['service' => GV_SERVICE, 'api' => 'v1', 'docs' => 'https://gravitverifier.space/docs/']); }

$auth = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
$acct = gv_account_for_key(preg_match('/^Bearer\s+(\S+)$/', $auth, $m) ? $m[1] : null);
if (!$acct) { err(401, 'missing or invalid API key (Authorization: Bearer gv_...)'); }

if ($path === '/v1/verify' && $method === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, GV_MAX_BODY + 1);
    if ($body === false || strlen($body) > GV_MAX_BODY) { err(413, 'request body larger than 1 MiB'); }
    if (!is_array(json_decode($body, true))) { err(400, 'request body must be a JSON object: {"artifact": {...}}'); }
    $u = gv_usage($acct);
    if ($u['used'] >= $u['limit']) { err(429, "monthly limit of {$u['limit']} verifications reached for plan {$u['plan']}"); }
    try { [$meta, $result] = gv_run_worker($body); } catch (Throwable $e) { err(500, 'the verifier could not run; please try again'); }
    if (empty($meta['ok'])) { err(422, $meta['error'] ?? 'artifact rejected'); }
    [$receipt, $sig, $hash] = gv_record($acct, $meta, $result);
    http_response_code(200);
    // The result is embedded byte for byte as the verifier produced it; result_sha256 in the receipt covers exactly these bytes.
    echo '{"result":' . $result . ',"receipt":' . gv_canon($receipt) . ',"signature":' . json_encode($sig) .
         ',"entry_hash":' . json_encode($hash) . '}';
    exit;
}

if ($path === '/v1/gate' && $method === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, GV_MAX_BODY + 1);
    if ($body === false || strlen($body) > GV_MAX_BODY) { err(413, 'request body larger than 1 MiB'); }
    $g = json_decode($body, true);
    if (!is_array($g)) { err(400, 'request body must be a JSON object: {"capability", "action", "policy"}'); }
    $u = gv_usage($acct);
    if ($u['used'] >= $u['limit']) { err(429, "monthly limit of {$u['limit']} calls reached for plan {$u['plan']}"); }
    $decision = null;
    if (isset($g['decision_id'])) {
        $st = gv_db()->prepare('SELECT decision_id, artifact_id, state, status FROM entries WHERE account_id = ? AND decision_id = ?
                                ORDER BY seq DESC LIMIT 1');
        $st->execute([$acct['id'], (string)$g['decision_id']]);
        $decision = $st->fetch() ?: null;
        if (!$decision) { err(404, 'no decision with this decision_id in your account'); }
    }
    unset($g['decision_id']);
    try { [$meta, $result] = gv_run_worker(json_encode(['gate' => $g, 'decision' => $decision], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)); }
    catch (Throwable $e) { err(500, 'the gate could not run; please try again'); }
    if (empty($meta['ok'])) { err(422, $meta['error'] ?? 'request rejected'); }
    [$receipt, $sig, $hash] = gv_record($acct, $meta, $result);
    http_response_code(200);
    echo '{"result":' . $result . ',"receipt":' . gv_canon($receipt) . ',"signature":' . json_encode($sig) .
         ',"entry_hash":' . json_encode($hash) . '}';
    exit;
}

if ($path === '/v1/usage' && $method === 'GET') { out(200, gv_usage($acct)); }

if ($path === '/v1/decisions' && $method === 'GET') {
    $limit = max(1, min(200, (int)($_GET['limit'] ?? 50)));
    $before = (int)($_GET['before_seq'] ?? PHP_INT_MAX);
    $st = gv_db()->prepare('SELECT seq, created, decision_id, artifact_id, state, status FROM entries
                            WHERE account_id = ? AND seq < ? ORDER BY seq DESC LIMIT ?');
    $st->execute([$acct['id'], $before, $limit]);
    out(200, ['decisions' => $st->fetchAll()]);
}

if (preg_match('#^/v1/decisions/([0-9a-f]{16})$#', $path, $m) && $method === 'GET') {
    $st = gv_db()->prepare('SELECT receipt, signature, entry_hash, result FROM entries WHERE account_id = ? AND decision_id = ?
                            ORDER BY seq DESC LIMIT 1');
    $st->execute([$acct['id'], $m[1]]);
    $r = $st->fetch();
    if (!$r) { err(404, 'no decision with this id in your account'); }
    echo '{"result":' . $r['result'] . ',"receipt":' . $r['receipt'] . ',"signature":' . json_encode($r['signature']) .
         ',"entry_hash":' . json_encode($r['entry_hash']) . '}';
    exit;
}

if ($path === '/v1/export' && $method === 'GET') {
    $from = max(1, (int)($_GET['from_seq'] ?? 1));
    $st = gv_db()->prepare('SELECT receipt, signature FROM entries WHERE account_id = ? AND seq >= ? ORDER BY seq LIMIT 10000');
    $st->execute([$acct['id'], $from]);
    $entries = array_map(fn($r) => '{"receipt":' . $r['receipt'] . ',"signature":' . json_encode($r['signature']) . '}', $st->fetchAll());
    echo '{"format":"gravit-verifier-export-1","service_key":' . gv_canon(gv_public_key_doc()) . ',"account":' .
         json_encode($acct['public_id']) . ',"entries":[' . implode(',', $entries) . ']}';
    exit;
}

err(404, 'unknown endpoint');
