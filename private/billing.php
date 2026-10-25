<?php
// Payments through BTCPay Server (Greenfield API) and in stablecoins (stablecoin.php). Prices are in Swiss francs (CHF),
// without VAT: the Foundation is a Swiss association and not VAT registered. Configuration: private/data/btcpay.json {"url", "store_id", "api_key", "webhook_secret"};
// the API key needs only btcpay.store.cancreateinvoice and btcpay.store.canviewinvoices (it cannot move funds).
declare(strict_types=1);

const GV_CURRENCY = 'CHF';
const GV_PRICES = ['pro' => 7, 'enterprise' => 150];   // CHF per 30 days
const GV_PRICES_YEAR = ['pro' => 60, 'enterprise' => 1440];   // CHF per year (365 days), launch price for the first year
const GV_BILLING_FROM = 'billing@gravitverifier.space';

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

/** Price in CHF for $months of $plan; 12 months = one year (365 days) at the annual price. */
function gv_price(string $plan, int $months): int {
    if (!isset(GV_PRICES[$plan]) || $months < 1 || $months > 12) { throw new InvalidArgumentException('plan must be pro or enterprise, months 1 to 12'); }
    return $months === 12 ? GV_PRICES_YEAR[$plan] : GV_PRICES[$plan] * $months;
}

function gv_payments_table(): void {
    $db = gv_db();
    $db->exec('CREATE TABLE IF NOT EXISTS payments (invoice_id TEXT PRIMARY KEY, account_id INTEGER NOT NULL REFERENCES accounts(id),
                   plan TEXT NOT NULL, months INTEGER NOT NULL, amount INTEGER NOT NULL, currency TEXT NOT NULL DEFAULT \'CHF\',
                   created TEXT NOT NULL, settled TEXT)');
    $cols = array_column($db->query('PRAGMA table_info(payments)')->fetchAll(), 'name');
    if (in_array('amount_usd', $cols, true)) {            // first version stored USD amounts; keep them, labelled USD
        $db->exec('ALTER TABLE payments RENAME COLUMN amount_usd TO amount');
        $db->exec("ALTER TABLE payments ADD COLUMN currency TEXT NOT NULL DEFAULT 'USD'");
    }
}

/** Create an invoice for $months of $plan. Returns ['invoice_id', 'checkout_url', 'amount', 'currency']. */
function gv_checkout(array $acct, string $plan, int $months): array {
    $c = gv_btcpay();
    if (!$c) { throw new DomainException('payments are not open yet'); }
    $amount = gv_price($plan, $months);
    $inv = gv_btcpay_call($c, 'POST', '/invoices', [
        'amount' => (string)$amount, 'currency' => GV_CURRENCY,
        'metadata' => ['orderId' => $acct['public_id'] . '-' . gmdate('YmdHis'), 'account' => $acct['public_id'], 'plan' => $plan,
                       'months' => $months, 'itemDesc' => $months === 12 ? "Gravit Verifier $plan, 1 year" : "Gravit Verifier $plan, $months x 30 days"],
        'checkout' => ['redirectURL' => 'https://gravitverifier.space/docs/?paid=1', 'redirectAutomatically' => true]]);
    gv_payments_table();
    gv_db()->prepare('INSERT INTO payments (invoice_id, account_id, plan, months, amount, currency, created) VALUES (?,?,?,?,?,?,?)')
        ->execute([$inv['id'], $acct['id'], $plan, $months, $amount, GV_CURRENCY, gv_now()]);
    return ['invoice_id' => $inv['id'], 'checkout_url' => $inv['checkoutLink'], 'amount' => $amount, 'currency' => GV_CURRENCY];
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
    return gv_settle($inv['id'], 'Bitcoin', fn(array $p) => (float)$inv['amount'] >= (float)$p['amount'] && ($inv['currency'] ?? '') === $p['currency']);
}

/** Extends the plan once per payment. $amountOk checks the payment row against what was really paid.
 *  $method names the means of payment in the receipt mail. Returns a short status string. */
function gv_settle(string $invoiceId, string $method, callable $amountOk): string {
    gv_payments_table();
    $db = gv_db();
    $db->beginTransaction();
    try {
        $st = $db->prepare('SELECT p.*, a.plan AS cur_plan, a.plan_until FROM payments p JOIN accounts a ON a.id = p.account_id
                            WHERE p.invoice_id = ? AND p.settled IS NULL');
        $st->execute([$invoiceId]);
        $p = $st->fetch();
        if (!$p) { $db->commit(); return 'already applied or unknown'; }
        if (!$amountOk($p)) { throw new RuntimeException('amount mismatch'); }
        $from = ($p['plan_until'] && $p['plan_until'] > gv_now() && $p['cur_plan'] === $p['plan']) ? strtotime($p['plan_until']) : time();
        $days = (int)$p['months'] === 12 ? 365 : 30 * (int)$p['months'];
        $until = gmdate('Y-m-d\TH:i:s\Z', $from + $days * 86400);
        $db->prepare('UPDATE accounts SET plan = ?, plan_until = ? WHERE id = ?')->execute([$p['plan'], $until, $p['account_id']]);
        $db->prepare('UPDATE payments SET settled = ? WHERE invoice_id = ?')->execute([gv_now(), $invoiceId]);
        $db->commit();
        $em = $db->prepare('SELECT email, public_id FROM accounts WHERE id = ?'); $em->execute([$p['account_id']]); $a = $em->fetch();
        if ($a && filter_var($a['email'], FILTER_VALIDATE_EMAIL)) { gv_billing_mail($a['email'], $a['public_id'], $p, $until, $invoiceId, false, $method); }
        gv_billing_mail(GV_BILLING_FROM, $a['public_id'] ?? '?', $p, $until, $invoiceId, true, $method);
        return "applied until $until";
    } catch (Throwable $e) { $db->rollBack(); throw $e; }
}

function gv_billing_mail(string $to, string $account, array $p, string $until, string $invoice, bool $internal = false,
                         string $method = 'Bitcoin'): void {
    $plan = ucfirst((string)$p['plan']); $months = (int)$p['months']; $day = substr($until, 0, 10);
    $price = ($p['currency'] ?? GV_CURRENCY) . ' ' . (int)$p['amount'];
    $term = $months === 12 ? '1 year' : "$months x 30 days";
    $subject = $internal ? "Payment settled: $plan, $price ($account)" : "Payment received: Gravit Verifier $plan until $day";
    $refund = $method === 'Bitcoin' ? 'in Bitcoin to an address you give us' : 'in the same stablecoin, to the address you paid from';
    $body = $internal ? "Invoice $invoice settled ($method). Account $account: $plan for $term, $price, valid until $until.\n" : <<<TXT
Hello,

thank you. Your payment of $price in $method has been confirmed.

Account: $account
Plan: $plan, $term
Valid until: $until (UTC)
Invoice: $invoice

Your API key stays the same. Check your plan at any time with GET https://gravitverifier.space/api/v1/usage

Money-back guarantee: if the plan is not right for you, reply to this email within 30 days of payment.
We refund the full amount, $refund. No questions asked.

No VAT is charged: the Gravit Open Network Foundation, a Swiss association, is not VAT registered. If you need an invoice
document for your accounting, simply reply to this email.

Questions? Reply to this email. A person reads every message.

Gravit Open Network Foundation, Zurich
https://gravitverifier.space
TXT;
    $headers = "From: Gravit Verifier Billing <" . GV_BILLING_FROM . ">\r\nReply-To: " . GV_BILLING_FROM .
               "\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit";
    @mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers, '-f' . GV_BILLING_FROM);
}
