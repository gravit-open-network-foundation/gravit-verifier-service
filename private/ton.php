<?php
// Payments in Toncoin (TON) straight to the Foundation's own wallet. Nothing here can move funds: the service only
// reads the wallet's public incoming transactions. Configuration: private/data/ton.json {"address": "UQ..."}.
// Without it, TON checkout stays closed.
//
// Each order gets a unique amount: the CHF price converted at the current TON/CHF rate, rounded up to 0.001 TON,
// plus a few nanotons. The rate is fixed when the order is created and the order is shown as valid for
// GV_TON_ORDER_HOURS, because the TON price moves. stablecoin_watch.php (cron) matches incoming transfers by
// exact amount and settles the order through gv_settle().
declare(strict_types=1);

require_once __DIR__ . '/billing.php';
require_once __DIR__ . '/stablecoin.php';   // shares the orders table

const GV_TON_API = 'https://toncenter.com/api/v2/getTransactions';
const GV_TON_RATE_URL = 'https://api.coingecko.com/api/v3/simple/price?ids=the-open-network&vs_currencies=chf';
const GV_TON_DECIMALS = 9;
const GV_TON_ORDER_HOURS = 2;
const GV_TON_MATCH_DAYS = 7;

function gv_ton_config(): ?array {
    $f = gv_dir() . '/data/ton.json';
    $c = file_exists($f) ? json_decode((string)file_get_contents($f), true) : null;
    if (!is_array($c) || !preg_match('/^[EU]Q[A-Za-z0-9_-]{46}$/', (string)($c['address'] ?? ''))) { return null; }
    return $c;
}

function gv_ton_get(string $url) {
    $ch = curl_init($url);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20, CURLOPT_FOLLOWLOCATION => true,
                            CURLOPT_USERAGENT => 'gravit-verifier-service', CURLOPT_HTTPHEADER => ['Accept: application/json']]);
    $out = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $d = json_decode((string)$out, true);
    if ($code !== 200 || !is_array($d)) { throw new RuntimeException("ton http $code"); }
    return $d;
}

/** CHF per TON, cached for 10 minutes. */
function gv_ton_rate(): string {
    $f = gv_dir() . '/data/ton_rate.json';
    $c = file_exists($f) ? json_decode((string)file_get_contents($f), true) : null;
    if (is_array($c) && ($c['fetched'] ?? 0) > time() - 600) { return $c['chf_per_ton']; }
    $rate = gv_ton_get(GV_TON_RATE_URL)['the-open-network']['chf'] ?? null;
    if (!is_numeric($rate) || $rate <= 0.01 || $rate > 1000) { throw new RuntimeException('no TON rate'); }
    $c = ['chf_per_ton' => (string)$rate, 'fetched' => time()];
    file_put_contents($f, json_encode($c), LOCK_EX);
    return $c['chf_per_ton'];
}

function gv_ton_format(int $nano): string {
    return intdiv($nano, 10 ** GV_TON_DECIMALS) . '.' . str_pad((string)($nano % 10 ** GV_TON_DECIMALS), GV_TON_DECIMALS, '0', STR_PAD_LEFT);
}

/** Create a TON order for $months of $plan. */
function gv_ton_checkout(array $acct, string $plan, int $months): array {
    $c = gv_ton_config();
    if (!$c) { throw new DomainException('TON payments are not open yet'); }
    $chf = gv_price($plan, $months);
    $rate = gv_ton_rate();
    $milli = (int)ceil(round($chf / (float)$rate * 1000, 6));   // 0.001 TON steps, rounded up
    gv_sc_tables();
    $db = gv_db();
    $taken = $db->prepare("SELECT 1 FROM stablecoin_orders WHERE network = 'ton' AND amount_units = ? AND settled IS NULL AND created > ?");
    $since = gmdate('Y-m-d\TH:i:s\Z', time() - GV_TON_MATCH_DAYS * 86400);
    for ($i = 0; ; $i++) {
        if ($i > 50) { throw new RuntimeException('no free amount'); }
        $nano = $milli * 10 ** (GV_TON_DECIMALS - 3) + random_int(1, 999999);
        $taken->execute([$nano, $since]);
        if (!$taken->fetchColumn()) { break; }
    }
    $id = gv_new_id('ton_', 12);
    $db->beginTransaction();
    $db->prepare('INSERT INTO payments (invoice_id, account_id, plan, months, amount, currency, created) VALUES (?,?,?,?,?,?,?)')
        ->execute([$id, $acct['id'], $plan, $months, $chf, GV_CURRENCY, gv_now()]);
    // from_block holds the order's Unix time: transfers older than the order are never matched
    $db->prepare('INSERT INTO stablecoin_orders (order_id, network, token, amount_units, usd_per_chf, from_block, created) VALUES (?,?,?,?,?,?,?)')
        ->execute([$id, 'ton', 'TON', $nano, $rate, time() - 60, gv_now()]);
    $db->commit();
    return gv_ton_order_doc($id, $acct['id']);
}

/** Public view of a TON order; null if it is not this account's. */
function gv_ton_order_doc(string $id, int $accountId): ?array {
    gv_sc_tables();
    $st = gv_db()->prepare("SELECT o.*, p.plan, p.months, p.amount AS chf FROM stablecoin_orders o
                            JOIN payments p ON p.invoice_id = o.order_id WHERE o.order_id = ? AND p.account_id = ? AND o.network = 'ton'");
    $st->execute([$id, $accountId]);
    $o = $st->fetch();
    if (!$o) { return null; }
    $c = gv_ton_config();
    return ['order_id' => $o['order_id'], 'plan' => $o['plan'], 'months' => (int)$o['months'],
            'price' => ['amount' => (int)$o['chf'], 'currency' => GV_CURRENCY, 'chf_per_ton' => $o['usd_per_chf']],
            'pay' => ['network' => 'ton', 'token' => 'TON', 'to' => $c['address'] ?? null,
                      'amount' => gv_ton_format((int)$o['amount_units']), 'amount_units' => (int)$o['amount_units']],
            'note' => 'Send exactly this amount, in one transfer, within ' . GV_TON_ORDER_HOURS . ' hours (the TON rate is fixed for that time). '
                      . 'The plan starts once the transfer appears on chain.',
            'status' => $o['settled'] ? 'paid' : 'waiting', 'tx_hash' => $o['tx_hash'], 'created' => $o['created'], 'paid' => $o['settled']];
}

/** Read the wallet's incoming transfers and settle matching orders. Returns log lines. */
function gv_ton_watch(): array {
    $c = gv_ton_config();
    if (!$c) { return []; }
    gv_sc_tables();
    $db = gv_db();
    $open = $db->prepare("SELECT order_id, amount_units, from_block FROM stablecoin_orders WHERE network = 'ton' AND settled IS NULL AND created > ?");
    $open->execute([gmdate('Y-m-d\TH:i:s\Z', time() - GV_TON_MATCH_DAYS * 86400)]);
    $orders = $open->fetchAll();
    if (!$orders) { return []; }
    $oldest = min(array_map(fn($o) => (int)$o['from_block'], $orders));
    $log = [];
    $cursor = '';
    for ($page = 0; $page < 20 && $orders; $page++) {
        $d = gv_ton_get(GV_TON_API . '?limit=50&archival=true&address=' . urlencode($c['address']) . $cursor);
        $txs = $d['result'] ?? [];
        if (empty($d['ok']) || !$txs) { break; }
        foreach ($txs as $t) {
            $in = $t['in_msg'] ?? [];
            if (($in['source'] ?? '') === '' || !ctype_digit((string)($in['value'] ?? ''))) { continue; }   // not an incoming transfer
            $nano = (int)$in['value'];
            $tx = $t['transaction_id']['lt'] . ':' . $t['transaction_id']['hash'];
            foreach ($orders as $k => $o) {
                if ((int)$o['amount_units'] !== $nano || (int)$t['utime'] < (int)$o['from_block']) { continue; }
                $used = $db->prepare('SELECT 1 FROM stablecoin_orders WHERE tx_hash = ?'); $used->execute([$tx]);
                if ($used->fetchColumn()) { continue; }
                $status = gv_settle($o['order_id'], 'TON', fn() => true);
                $db->prepare('UPDATE stablecoin_orders SET tx_hash = ?, settled = ? WHERE order_id = ? AND settled IS NULL')
                    ->execute([$tx, gv_now(), $o['order_id']]);
                $log[] = $o['order_id'] . " $status tx $tx";
                unset($orders[$k]);
                break;
            }
        }
        $last = end($txs);
        if ((int)$last['utime'] < $oldest) { break; }
        $cursor = '&lt=' . $last['transaction_id']['lt'] . '&hash=' . urlencode($last['transaction_id']['hash']);
    }
    return $log;
}
