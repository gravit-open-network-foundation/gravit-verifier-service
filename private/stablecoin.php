<?php
// Payments in stablecoins (USDC, USDT) straight to the Foundation's own address. Nothing here can move funds:
// the service only reads public blockchain logs. Configuration: private/data/stablecoin.json
// {"address": "0x...", "networks": ["ethereum", "base"]}. Without it, stablecoin checkout stays closed.
//
// Each order gets a unique amount (the CHF price converted to USD at the ECB rate, rounded up to the cent, plus
// a few millionths), so an incoming transfer is matched to its order by network, token and exact amount.
// stablecoin_watch.php (cron) scans the Transfer logs and settles matched orders through gv_settle().
declare(strict_types=1);

require_once __DIR__ . '/billing.php';

const GV_SC_NETWORKS = [
    'ethereum' => ['chain_id' => 1, 'rpc' => 'https://ethereum-rpc.publicnode.com', 'confirmations' => 12,
                   'tokens' => ['USDC' => '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
                                'USDT' => '0xdac17f958d2ee523a2206206994597c13d831ec7']],
    'base'     => ['chain_id' => 8453, 'rpc' => 'https://base-rpc.publicnode.com', 'confirmations' => 30,
                   'tokens' => ['USDC' => '0x833589fcd6edb6e08f4c7c32d4f71b54bda02913']],
];
const GV_SC_DECIMALS = 6;                 // USDC and USDT on these networks
const GV_SC_ORDER_HOURS = 24;             // shown to the customer
const GV_SC_MATCH_DAYS = 7;               // a late transfer is still matched within this window
const GV_SC_TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';
const GV_SC_FX_URL = 'https://api.frankfurter.dev/v1/latest?base=CHF&symbols=USD';   // ECB reference rates

function gv_sc_config(): ?array {
    $f = gv_dir() . '/data/stablecoin.json';
    $c = file_exists($f) ? json_decode((string)file_get_contents($f), true) : null;
    if (!is_array($c) || !preg_match('/^0x[0-9a-fA-F]{40}$/', (string)($c['address'] ?? ''))) { return null; }
    $c['address'] = strtolower($c['address']);
    $c['networks'] = array_values(array_intersect($c['networks'] ?? array_keys(GV_SC_NETWORKS), array_keys(GV_SC_NETWORKS)));
    return $c['networks'] ? $c : null;
}

function gv_sc_tables(): void {
    gv_payments_table();
    gv_db()->exec('CREATE TABLE IF NOT EXISTS stablecoin_orders (order_id TEXT PRIMARY KEY REFERENCES payments(invoice_id),
                     network TEXT NOT NULL, token TEXT NOT NULL, amount_units INTEGER NOT NULL, usd_per_chf TEXT NOT NULL,
                     from_block INTEGER NOT NULL, created TEXT NOT NULL, tx_hash TEXT UNIQUE, settled TEXT)');
    gv_db()->exec('CREATE TABLE IF NOT EXISTS stablecoin_scan (network TEXT PRIMARY KEY, last_block INTEGER NOT NULL)');
}

function gv_sc_rpc(string $network, string $method, array $params) {
    $ch = curl_init(GV_SC_NETWORKS[$network]['rpc']);
    curl_setopt_array($ch, [CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_POSTFIELDS => json_encode(['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => $params])]);
    $out = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $d = json_decode((string)$out, true);
    if ($code !== 200 || !is_array($d) || !array_key_exists('result', $d)) { throw new RuntimeException("rpc $network $method $code"); }
    return $d['result'];
}

function gv_sc_block(string $network): int { return (int)hexdec(substr((string)gv_sc_rpc($network, 'eth_blockNumber', []), 2)); }

/** USD per CHF from the ECB reference rate, cached for 6 hours. */
function gv_sc_rate(): string {
    $f = gv_dir() . '/data/fx.json';
    $c = file_exists($f) ? json_decode((string)file_get_contents($f), true) : null;
    if (is_array($c) && ($c['fetched'] ?? 0) > time() - 6 * 3600) { return $c['usd_per_chf']; }
    $ch = curl_init(GV_SC_FX_URL);
    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 10, CURLOPT_FOLLOWLOCATION => true]);
    $d = json_decode((string)curl_exec($ch), true); curl_close($ch);
    $rate = $d['rates']['USD'] ?? null;
    if (!is_numeric($rate) || $rate < 0.5 || $rate > 3) {
        if (is_array($c)) { return $c['usd_per_chf']; }   // a stale rate is better than no checkout
        throw new RuntimeException('no exchange rate');
    }
    $c = ['usd_per_chf' => (string)$rate, 'date' => $d['date'] ?? '', 'fetched' => time()];
    file_put_contents($f, json_encode($c), LOCK_EX);
    return $c['usd_per_chf'];
}

function gv_sc_format(int $units): string {
    return intdiv($units, 10 ** GV_SC_DECIMALS) . '.' . str_pad((string)($units % 10 ** GV_SC_DECIMALS), GV_SC_DECIMALS, '0', STR_PAD_LEFT);
}

/** Create a stablecoin order for $months of $plan. */
function gv_sc_checkout(array $acct, string $plan, int $months, string $network, string $token): array {
    $c = gv_sc_config();
    if (!$c) { throw new DomainException('stablecoin payments are not open yet'); }
    if (!in_array($network, $c['networks'], true) || !isset(GV_SC_NETWORKS[$network]['tokens'][$token])) {
        throw new InvalidArgumentException('network/token must be one of: ' . implode(', ', gv_sc_options($c)));
    }
    $chf = gv_price($plan, $months);
    $rate = gv_sc_rate();
    $cents = (int)ceil(round($chf * (float)$rate * 100, 6));
    gv_sc_tables();
    $db = gv_db();
    $taken = $db->prepare('SELECT 1 FROM stablecoin_orders WHERE network = ? AND token = ? AND amount_units = ? AND settled IS NULL
                           AND created > ?');
    $since = gmdate('Y-m-d\TH:i:s\Z', time() - GV_SC_MATCH_DAYS * 86400);
    for ($i = 0; ; $i++) {
        if ($i > 50) { throw new RuntimeException('no free amount'); }
        $units = $cents * 10 ** (GV_SC_DECIMALS - 2) + random_int(1, 9999);
        $taken->execute([$network, $token, $units, $since]);
        if (!$taken->fetchColumn()) { break; }
    }
    $from = max(0, gv_sc_block($network) - 5);
    $id = gv_new_id('sc_', 12);
    $db->beginTransaction();
    $db->prepare('INSERT INTO payments (invoice_id, account_id, plan, months, amount, currency, created) VALUES (?,?,?,?,?,?,?)')
        ->execute([$id, $acct['id'], $plan, $months, $chf, GV_CURRENCY, gv_now()]);
    $db->prepare('INSERT INTO stablecoin_orders (order_id, network, token, amount_units, usd_per_chf, from_block, created) VALUES (?,?,?,?,?,?,?)')
        ->execute([$id, $network, $token, $units, $rate, $from, gv_now()]);
    $db->commit();
    return gv_sc_order_doc($id, $acct['id']);
}

function gv_sc_options(array $c): array {
    $o = [];
    foreach ($c['networks'] as $n) { foreach (array_keys(GV_SC_NETWORKS[$n]['tokens']) as $t) { $o[] = "$n/$t"; } }
    return $o;
}

/** Public view of an order; null if it is not this account's. */
function gv_sc_order_doc(string $id, int $accountId): ?array {
    gv_sc_tables();
    $st = gv_db()->prepare('SELECT o.*, p.plan, p.months, p.amount AS chf, p.account_id FROM stablecoin_orders o
                            JOIN payments p ON p.invoice_id = o.order_id WHERE o.order_id = ? AND p.account_id = ?');
    $st->execute([$id, $accountId]);
    $o = $st->fetch();
    if (!$o) { return null; }
    $c = gv_sc_config();
    $net = GV_SC_NETWORKS[$o['network']];
    return ['order_id' => $o['order_id'], 'plan' => $o['plan'], 'months' => (int)$o['months'],
            'price' => ['amount' => (int)$o['chf'], 'currency' => GV_CURRENCY, 'usd_per_chf' => $o['usd_per_chf']],
            'pay' => ['network' => $o['network'], 'chain_id' => $net['chain_id'], 'token' => $o['token'],
                      'token_contract' => $net['tokens'][$o['token']], 'to' => $c['address'] ?? null,
                      'amount' => gv_sc_format((int)$o['amount_units']), 'amount_units' => (int)$o['amount_units']],
            'note' => 'Send exactly this amount, in one transfer, within ' . GV_SC_ORDER_HOURS . ' hours. The plan starts after '
                      . $net['confirmations'] . ' confirmations.',
            'status' => $o['settled'] ? 'paid' : 'waiting', 'tx_hash' => $o['tx_hash'], 'created' => $o['created'], 'paid' => $o['settled']];
}

/** Scan new Transfer logs to the Foundation's address and settle matching orders. Returns log lines. */
function gv_sc_watch(): array {
    $c = gv_sc_config();
    if (!$c) { return ['not configured']; }
    gv_sc_tables();
    $db = gv_db();
    $log = [];
    $since = gmdate('Y-m-d\TH:i:s\Z', time() - GV_SC_MATCH_DAYS * 86400);
    $to = '0x' . str_pad(substr($c['address'], 2), 64, '0', STR_PAD_LEFT);
    foreach ($c['networks'] as $network) {
        $open = $db->prepare('SELECT order_id, token, amount_units, from_block FROM stablecoin_orders
                              WHERE network = ? AND settled IS NULL AND created > ?');
        $open->execute([$network, $since]);
        $orders = $open->fetchAll();
        if (!$orders) { continue; }
        $safe = gv_sc_block($network) - GV_SC_NETWORKS[$network]['confirmations'];
        $st = $db->prepare('SELECT last_block FROM stablecoin_scan WHERE network = ?'); $st->execute([$network]);
        $last = $st->fetchColumn();
        $start = min(array_map(fn($o) => (int)$o['from_block'], $orders));
        if ($last !== false) { $start = max($start, (int)$last + 1); }
        for ($a = $start; $a <= $safe; $a += 2000) {
            $b = min($safe, $a + 1999);
            foreach (GV_SC_NETWORKS[$network]['tokens'] as $token => $contract) {
                $logs = gv_sc_rpc($network, 'eth_getLogs', [['fromBlock' => '0x' . dechex($a), 'toBlock' => '0x' . dechex($b),
                    'address' => $contract, 'topics' => [GV_SC_TRANSFER_TOPIC, null, $to]]]);
                foreach ($logs as $l) {
                    $hex = ltrim(substr((string)$l['data'], 2), '0');
                    if ($hex === '' || strlen($hex) > 15) { continue; }   // zero, or far above any price
                    $units = (int)hexdec($hex);
                    $block = (int)hexdec(substr((string)$l['blockNumber'], 2));
                    foreach ($orders as $k => $o) {
                        if ($o['token'] !== $token || (int)$o['amount_units'] !== $units || $block < (int)$o['from_block']) { continue; }
                        $tx = strtolower((string)$l['transactionHash']);
                        $used = $db->prepare('SELECT 1 FROM stablecoin_orders WHERE tx_hash = ?'); $used->execute([$tx]);
                        if ($used->fetchColumn()) { continue; }
                        $status = gv_settle($o['order_id'], "$token on " . ucfirst($network), fn() => true);
                        $db->prepare('UPDATE stablecoin_orders SET tx_hash = ?, settled = ? WHERE order_id = ? AND settled IS NULL')
                            ->execute([$tx, gv_now(), $o['order_id']]);
                        $log[] = $o['order_id'] . " $status tx $tx";
                        unset($orders[$k]);   // one transfer per order
                        break;
                    }
                }
            }
            $db->prepare('INSERT INTO stablecoin_scan (network, last_block) VALUES (?, ?)
                          ON CONFLICT(network) DO UPDATE SET last_block = excluded.last_block')->execute([$network, $b]);
        }
    }
    return $log;
}
