<?php
// Payments through BTCPay Server (Greenfield API). Prices are in USD, without VAT: the Foundation is not
// VAT registered. Configuration: private/data/btcpay.json {"url", "store_id", "api_key", "webhook_secret"};
// the API key needs only btcpay.store.cancreateinvoice and btcpay.store.canviewinvoices (it cannot move funds).
declare(strict_types=1);

const GV_PRICES_USD = ['pro' => 7, 'enterprise' => 150];   // per 30 days

function gv_btcpay(): ?array {
    $f = gv_dir() . '/data/btcpay.json';
    $c = file_exists($f) ? json_decode((string)file_get_contents($f), true) : null;
    return (is_array($c) && !empty($c['url']) && !empty($c['store_id']) && !empty($c['api_key'])) ? $c : null;
}

function gv_btcpay_call(array $c, string $method, string $path, ?array $body = null): array {
    $ch = curl_init(rtrim($c['url'], '/') . '/api/v1/stores/' . rawurlencode($c['store_id']) . $path);
    curl_setopt_array($ch, [CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_TIMEOUT => 20,
        CURLOPT_HTTPHEADER => ['Authorization: token ' . $c['api_key'], 'Content-Type: application/json']]);
    if ($body !== null) { curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body)); }
    $out = curl_exec($ch); $code = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
    $d = json_decode((string)$out, true);
    if ($code < 200 || $code >= 300 || !is_array($d)) { throw new RuntimeException("btcpay $code"); }
    return $d;
}

function gv_payments_table(): void {
    gv_db()->exec('CREATE TABLE IF NOT EXISTS payments (invoice_id TEXT PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id),
                   plan TEXT NOT NULL, months INTEGER NOT NULL, amount_usd INTEGER NOT NULL, created TEXT NOT NULL, settled TEXT)');
}

/** Create an invoice for $months of $plan. Returns ['invoice_id', 'checkout_url', 'amount_usd']. */
function gv_checkout(array $acct, string $plan, int $months): array {
    $c = gv_btcpay();
    if (!$c) { throw new DomainException('payments are not open yet'); }
    if (!isset(GV_PRICES_USD[$plan]) || $months < 1 || $months > 12) { throw new InvalidArgumentException('plan must be pro or enterprise, months 1 to 12'); }
    $amount = GV_PRICES_USD[$plan] * $months;
    $inv = gv_btcpay_call($c, 'POST', '/invoices', [
        'amount' => (string)$amount, 'currency' => 'USD',
        'metadata' => ['orderId' => $acct['public_id'] . '-' . gmdate('YmdHis'), 'account' => $acct['public_id'], 'plan' => $plan,
                       'months' => $months, 'itemDesc' => "Gravit Verifier $plan, $months x 30 days"],
        'checkout' => ['redirectURL' => 'https://gravitverifier.space/docs/?paid=1', 'redirectAutomatically' => true]]);
    gv_payments_table();
    gv_db()->prepare('INSERT INTO payments (invoice_id, account_id, plan, months, amount_usd, created) VALUES (?,?,?,?,?,?)')
        ->execute([$inv['id'], $acct['id'], $plan, $months, $amount, gv_now()]);
    return ['invoice_id' => $inv['id'], 'checkout_url' => $inv['checkoutLink'], 'amount_usd' => $amount];
}

/** BTCPay webhook. Verifies the HMAC, then re-reads the invoice from BTCPay (the webhook body is never
 *  trusted for amounts) and extends the plan once per invoice. Returns a short status string. */
function gv_webhook(string $raw, string $sigHeader): string {
    $c = gv_btcpay();
    if (!$c || empty($c['webhook_secret'])) { return 'not configured'; }
    if (!hash_equals('sha256=' . hash_hmac('sha256', $raw, $c['webhook_secret']), $sigHeader)) { throw new RuntimeException('bad signature'); }
    $ev = json_decode($raw, true);
    if (($ev['type'] ?? '') !== 'InvoiceSettled' || empty($ev['invoiceId'])) { return 'ignored'; }
    $inv = gv_btcpay_call($c, 'GET', '/invoices/' . rawurlencode($ev['invoiceId']));
    if (($inv['status'] ?? '') !== 'Settled') { return 'not settled'; }
    gv_payments_table();
    $db = gv_db();
    $db->beginTransaction();
    try {
        $st = $db->prepare('SELECT p.*, a.plan AS cur_plan, a.plan_until FROM payments p JOIN accounts a ON a.id = p.account_id
                            WHERE p.invoice_id = ? AND p.settled IS NULL');
        $st->execute([$inv['id']]);
        $p = $st->fetch();
        if (!$p) { $db->commit(); return 'already applied or unknown'; }
        if ((float)$inv['amount'] < (float)$p['amount_usd'] || ($inv['currency'] ?? '') !== 'USD') { throw new RuntimeException('amount mismatch'); }
        $from = ($p['plan_until'] && $p['plan_until'] > gv_now() && $p['cur_plan'] === $p['plan']) ? strtotime($p['plan_until']) : time();
        $until = gmdate('Y-m-d\TH:i:s\Z', $from + 30 * 86400 * (int)$p['months']);
        $db->prepare('UPDATE accounts SET plan = ?, plan_until = ? WHERE id = ?')->execute([$p['plan'], $until, $p['account_id']]);
        $db->prepare('UPDATE payments SET settled = ? WHERE invoice_id = ?')->execute([gv_now(), $inv['id']]);
        $db->commit();
        return "applied until $until";
    } catch (Throwable $e) { $db->rollBack(); throw $e; }
}
