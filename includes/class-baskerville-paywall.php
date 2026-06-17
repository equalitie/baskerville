<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Pay-per-crawl policy engine — X402 V2 / Coinbase facilitator.
 *
 * Hooked at template_redirect priority 1 (after log_page_visit at 0).
 * Flow:
 *   1. Check BV1 grant token (subsequent requests after payment)
 *   2. Check PAYMENT-SIGNATURE header → verify + settle via Coinbase → issue BV1 grant
 *   3. Check ai_score → return 402 if above threshold
 */
class Baskerville_Paywall {

	private Baskerville_Core $core;
	private Baskerville_Pay_Storage $storage;
	private Baskerville_Pay_Grant $grant;
	private Baskerville_Stats $stats;
	private Baskerville_AI_UA $aiua;

	// USDC contract addresses per CAIP-2 network
	private const USDC_CONTRACTS = [
		'eip155:137'   => '0x3c499c542cEF5E3811e1192ce70d8cC03d5c3359', // Polygon mainnet
		'eip155:84532' => '0x036CbD53842c5426634e7929541eC2318f3dCF7e', // Base Sepolia testnet
	];

	// Network slug → CAIP-2
	private const NETWORK_MAP = [
		'polygon'      => 'eip155:137',
		'base-sepolia' => 'eip155:84532',
	];

	public function __construct(
		Baskerville_Core $core,
		Baskerville_Pay_Storage $storage,
		Baskerville_Pay_Grant $grant,
		Baskerville_Stats $stats,
		Baskerville_AI_UA $aiua
	) {
		$this->core    = $core;
		$this->storage = $storage;
		$this->grant   = $grant;
		$this->stats   = $stats;
		$this->aiua    = $aiua;
	}

	// -------------------------------------------------------------------------
	// /eq402 test route
	// -------------------------------------------------------------------------

	public function init_eq402(): void {
		add_action('init', [$this, 'register_eq402_route']);
		add_filter('query_vars', [$this, 'add_eq402_query_var']);
		add_action('template_redirect', [$this, 'handle_eq402'], -1);
	}

	public function add_eq402_query_var(array $vars): array {
		$vars[] = 'baskerville_eq402';
		return $vars;
	}

	public function register_eq402_route(): void {
		add_rewrite_rule(
			'^eq402/?$',
			'index.php?baskerville_eq402=1',
			'top'
		);
	}

	/**
	 * Handle /eq402 requests — always behind paywall (no ai_score check).
	 */
	public function handle_eq402(): void {
		if (!get_query_var('baskerville_eq402')) {
			return;
		}

		if (!defined('DONOTCACHEPAGE')) {
			define('DONOTCACHEPAGE', true);
		}

		$options     = get_option('baskerville_settings', []);
		$pay_enabled = !empty($options['pay_enabled']);
		$pay_mode    = $options['pay_mode'] ?? 'off';

		if (!$pay_enabled || !in_array($pay_mode, ['enforce', 'test'], true)) {
			status_header(503);
			nocache_headers();
			header('Content-Type: text/plain');
			echo 'eq402 test page requires pay_enabled=true and pay_mode=enforce or test';
			exit;
		}

		$canonical_url = $this->canonical_url();
		$method        = strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'] ?? 'GET')));

		// Check BV1 grant (subsequent requests)
		$grant_token = $this->get_grant_token();
		if ($grant_token) {
			$payload = $this->grant->validate($grant_token, $canonical_url, $method);
			if ($payload !== null) {
				$this->render_eq402_success($payload, $options);
				exit;
			}
		}

		// Check X402 PAYMENT-SIGNATURE
		$payment_sig = $this->get_payment_signature();
		if ($payment_sig) {
			$requirements = $this->build_payment_requirements($canonical_url, $options);
			$verify       = $this->verify_x402_payment($payment_sig, $requirements, $options);

			if (!empty($verify['isValid'])) {
				$tx_hash = $verify['transaction'] ?? '';

				// Double-spend prevention: reject if this tx was already redeemed
				if ($tx_hash && $this->storage->receipt_exists($tx_hash)) {
					$this->send_402($canonical_url, 0, $options);
					exit;
				}

				$settle = $this->settle_x402_payment($payment_sig, $requirements, $options);

				if (!empty($settle['success'])) {
					$tx_hash = $settle['transaction'] ?? $tx_hash;

					// Record receipt to prevent replay
					if ($tx_hash) {
						$this->storage->insert_receipt([
							'tx_hash'        => $tx_hash,
							'req_id'         => 'x402',
							'amount'         => $requirements['amount'] ?? '0',
							'currency'       => 'USDC',
							'network'        => $requirements['network'] ?? '',
							'wallet_address' => $requirements['payTo'] ?? '',
							'asset_type'     => 'erc20',
							'token_contract' => $requirements['asset'] ?? '',
							'raw_json'       => (string) wp_json_encode($settle),
						]);
					}

					$grant_ttl  = (int) ($options['pay_grant_ttl'] ?? 900);
					$grant_data = $this->grant->mint('x402', $canonical_url, $grant_ttl);
					$token      = $grant_data['grant'];

					$this->set_grant_cookie($token, $canonical_url, $grant_ttl);

					if (!headers_sent()) {
						header('X-PAYMENT-RESPONSE: ' . base64_encode(wp_json_encode([
							'success'     => true,
							'transaction' => $tx_hash,
							'network'     => $settle['network'] ?? '',
							'payer'       => $settle['payer'] ?? '',
						])));
						header('Baskerville-Grant: ' . $token);
					}

					$payload = ['exp' => time() + $grant_ttl, 'url' => $canonical_url, 'req_id' => ''];
					$this->render_eq402_success($payload, $options, $settle);
					exit;
				}
			}
		}

		// Always 402 for /eq402
		$this->send_402($canonical_url, 100, $options);
		exit;
	}

	private function render_eq402_success(array $grant_payload, array $options, array $settle = []): void {
		$amount   = $options['pay_price'] ?? '0.10';
		$currency = 'USDC';
		$ttl      = (int) ($options['pay_grant_ttl'] ?? 900);
		$exp      = (int) ($grant_payload['exp'] ?? 0);
		$url      = $grant_payload['url'] ?? '';
		$tx       = $settle['transaction'] ?? '';
		$payer    = $settle['payer'] ?? '';

		status_header(200);
		nocache_headers();
		header('Content-Type: text/html; charset=utf-8');
		?>
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>eq402 — Payment Verified</title>
	<style>
		body { font-family: monospace; max-width: 600px; margin: 40px auto; padding: 0 20px; color: #222; }
		h1 { color: #2e7d32; }
		dl { line-height: 1.8; }
		dt { font-weight: bold; }
		dd { margin-left: 20px; word-break: break-all; }
	</style>
</head>
<body>
	<h1>Congratulations!</h1>
	<p>You successfully paid to access this page via the Baskerville X402 paywall.</p>
	<dl>
		<dt>Amount paid</dt>
		<dd><?php echo esc_html($amount . ' ' . $currency); ?></dd>
		<dt>Grant TTL</dt>
		<dd><?php echo esc_html($ttl); ?> seconds</dd>
		<dt>Expires at</dt>
		<dd><?php echo $exp ? esc_html(gmdate('c', $exp)) : 'n/a'; ?></dd>
		<dt>Canonical URL</dt>
		<dd><?php echo esc_html($url); ?></dd>
		<?php if ($tx): ?>
		<dt>Transaction</dt>
		<dd><?php echo esc_html($tx); ?></dd>
		<?php endif; ?>
		<?php if ($payer): ?>
		<dt>Payer</dt>
		<dd><?php echo esc_html($payer); ?></dd>
		<?php endif; ?>
	</dl>
</body>
</html>
		<?php
	}

	// -------------------------------------------------------------------------
	// Main paywall check
	// -------------------------------------------------------------------------

	public function check_paywall(): void {
		$options = get_option('baskerville_settings', []);

		// 1. Quick exits
		$pay_enabled = !empty($options['pay_enabled']);
		$pay_mode    = $options['pay_mode'] ?? 'off';
		if (!$pay_enabled || $pay_mode === 'off' || $pay_mode === 'test') {
			return;
		}

		$method = strtoupper(sanitize_text_field(wp_unslash($_SERVER['REQUEST_METHOD'] ?? 'GET')));
		if (!in_array($method, ['GET', 'HEAD'], true)) {
			return;
		}

		if (is_user_logged_in()) {
			return;
		}

		if (is_admin() || (defined('REST_REQUEST') && REST_REQUEST) || wp_doing_ajax()) {
			return;
		}

		$uri  = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
		$path = wp_parse_url($uri, PHP_URL_PATH) ?: '/';

		if (!$this->path_matches($path, $options)) {
			return;
		}

		$canonical_url = $this->canonical_url();

		// 2. Check BV1 grant token (subsequent requests after payment)
		$grant_token = $this->get_grant_token();
		if ($grant_token) {
			$payload = $this->grant->validate($grant_token, $canonical_url, $method);
			if ($payload !== null) {
				return;
			}
		}

		// 3. Check X402 PAYMENT-SIGNATURE header
		$payment_sig = $this->get_payment_signature();
		if ($payment_sig) {
			$requirements = $this->build_payment_requirements($canonical_url, $options);
			$verify       = $this->verify_x402_payment($payment_sig, $requirements, $options);

			if (!empty($verify['isValid'])) {
				$tx_hash = $verify['transaction'] ?? '';

				// Double-spend prevention: reject if this tx was already redeemed
				if ($tx_hash && $this->storage->receipt_exists($tx_hash)) {
					if ($pay_mode === 'enforce') {
						$this->send_402($canonical_url, 0, $options);
						exit;
					}
					return;
				}

				$settle = $this->settle_x402_payment($payment_sig, $requirements, $options);

				if (!empty($settle['success'])) {
					$tx_hash = $settle['transaction'] ?? $tx_hash;

					// Record receipt to prevent replay
					if ($tx_hash) {
						$this->storage->insert_receipt([
							'tx_hash'        => $tx_hash,
							'req_id'         => 'x402',
							'amount'         => $requirements['amount'] ?? '0',
							'currency'       => 'USDC',
							'network'        => $requirements['network'] ?? '',
							'wallet_address' => $requirements['payTo'] ?? '',
							'asset_type'     => 'erc20',
							'token_contract' => $requirements['asset'] ?? '',
							'raw_json'       => (string) wp_json_encode($settle),
						]);
					}

					$grant_ttl  = (int) ($options['pay_grant_ttl'] ?? 900);
					$grant_data = $this->grant->mint('x402', $canonical_url, $grant_ttl);
					$token      = $grant_data['grant'];

					$this->set_grant_cookie($token, $canonical_url, $grant_ttl);

					if (!headers_sent()) {
						header('X-PAYMENT-RESPONSE: ' . base64_encode(wp_json_encode([
							'success'     => true,
							'transaction' => $tx_hash,
							'network'     => $settle['network'] ?? '',
							'payer'       => $settle['payer'] ?? '',
						])));
						header('Baskerville-Grant: ' . $token);
					}

					return; // Allow access
				}
			}

			// Payment signature present but invalid — always 402 in enforce mode
			if ($pay_mode === 'enforce') {
				$this->send_402($canonical_url, 0, $options);
				exit;
			}
			return;
		}

		// 4. Get ai_score
		$ai_score = $this->get_ai_score();

		// 5. Check threshold
		$threshold = (int) ($options['pay_ai_threshold'] ?? 70);
		if ($ai_score < $threshold) {
			return;
		}

		// 6. Observe mode
		if ($pay_mode === 'observe') {
			if (!headers_sent()) {
				header('Baskerville-Paywall: would-402');
			}
			return;
		}

		// 7. Enforce mode
		if ($pay_mode === 'enforce') {
			$this->send_402($canonical_url, $ai_score, $options);
			exit;
		}
	}

	// -------------------------------------------------------------------------
	// X402 helpers
	// -------------------------------------------------------------------------

	/**
	 * Read PAYMENT-SIGNATURE (X402 V2) or X-PAYMENT (X402 V1 legacy) header.
	 */
	private function get_payment_signature(): ?string {
		$sig = isset($_SERVER['HTTP_PAYMENT_SIGNATURE'])
			? sanitize_text_field(wp_unslash($_SERVER['HTTP_PAYMENT_SIGNATURE']))
			: '';
		if ($sig) return $sig;

		$sig = isset($_SERVER['HTTP_X_PAYMENT'])
			? sanitize_text_field(wp_unslash($_SERVER['HTTP_X_PAYMENT']))
			: '';
		return $sig ?: null;
	}

	/**
	 * Build X402 payment requirements object for a URL.
	 */
	private function build_payment_requirements(string $canonical_url, array $options): array {
		$price   = $options['pay_price'] ?? '0.10';
		$network = $options['pay_network'] ?? 'polygon';
		$wallet  = $options['pay_wallet_address'] ?? '';

		$caip2 = self::NETWORK_MAP[$network] ?? 'eip155:137';
		$asset = self::USDC_CONTRACTS[$caip2] ?? self::USDC_CONTRACTS['eip155:137'];

		// USDC has 6 decimals: 0.10 USDC = 100000 atomic units
		$amount = (string) (int) round(floatval($price) * 1000000);

		return [
			'scheme'            => 'exact',
			'network'           => $caip2,
			'asset'             => $asset,
			'amount'            => $amount,
			'payTo'             => $wallet,
			'maxTimeoutSeconds' => 60,
			'extra'             => [
				'assetTransferMethod' => 'eip3009',
				'name'                => 'USD Coin',
				'version'             => '2',
			],
		];
	}

	/**
	 * Send X402 V2 response with PAYMENT-REQUIRED header.
	 */
	private function send_402(string $canonical_url, int $ai_score, array $options): void {
		$requirements = $this->build_payment_requirements($canonical_url, $options);

		$payment_required = [
			'x402Version' => 2,
			'resource'    => [
				'url'         => $canonical_url,
				'description' => 'Content access requires payment',
				'mimeType'    => 'text/html',
			],
			'accepts'     => [$requirements],
		];

		status_header(402);
		nocache_headers();
		header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true);
		header('Vary: Authorization, Cookie', false);
		header('Content-Type: application/json');
		header('PAYMENT-REQUIRED: ' . base64_encode(wp_json_encode($payment_required)));
		header('Baskerville-Reason: ai_score=' . $ai_score . ';policy=paywall');

		echo wp_json_encode([
			'error'           => 'payment_required',
			'x402Version'     => 2,
			'paymentRequired' => $payment_required,
		]);
	}

	/**
	 * Verify X402 payment with Coinbase facilitator.
	 */
	private function verify_x402_payment(string $payment_sig_b64, array $requirements, array $options): array {
		$payment_payload = json_decode(base64_decode($payment_sig_b64), true);
		if (!is_array($payment_payload)) {
			return ['isValid' => false, 'invalidReason' => 'malformed_header'];
		}

		$key_id   = $options['pay_cdp_key_id'] ?? '';
		$priv_key = $options['pay_cdp_private_key'] ?? '';

		if (!$key_id || !$priv_key) {
			error_log('Baskerville verify_x402_payment: CDP credentials not configured');
			return ['isValid' => false, 'invalidReason' => 'no_cdp_credentials'];
		}

		$path = '/platform/v2/x402/verify';
		$jwt  = $this->generate_cdp_jwt($key_id, $priv_key, 'POST', $path);

		if (!$jwt) {
			return ['isValid' => false, 'invalidReason' => 'jwt_generation_failed'];
		}

		$response = wp_remote_post('https://api.cdp.coinbase.com' . $path, [
			'headers' => [
				'Content-Type'  => 'application/json',
				'Authorization' => 'Bearer ' . $jwt,
			],
			'body'    => wp_json_encode([
				'x402Version'         => 2,
				'paymentPayload'      => $payment_payload,
				'paymentRequirements' => $requirements,
			]),
			'timeout' => 10,
		]);

		if (is_wp_error($response)) {
			error_log('Baskerville verify_x402: facilitator unreachable — ' . $response->get_error_message());
			return ['isValid' => false, 'invalidReason' => 'facilitator_unreachable'];
		}

		$body   = wp_remote_retrieve_body($response);
		$status = wp_remote_retrieve_response_code($response);
		error_log('Baskerville verify_x402: Coinbase status=' . $status . ' body=' . $body);

		$result = json_decode($body, true);
		return is_array($result) ? $result : ['isValid' => false, 'invalidReason' => 'invalid_response'];
	}

	/**
	 * Settle X402 payment with Coinbase facilitator (executes on-chain transfer).
	 */
	private function settle_x402_payment(string $payment_sig_b64, array $requirements, array $options): array {
		$payment_payload = json_decode(base64_decode($payment_sig_b64), true);
		if (!is_array($payment_payload)) {
			return ['success' => false];
		}

		$key_id   = $options['pay_cdp_key_id'] ?? '';
		$priv_key = $options['pay_cdp_private_key'] ?? '';

		$path = '/platform/v2/x402/settle';
		$jwt  = $this->generate_cdp_jwt($key_id, $priv_key, 'POST', $path);

		if (!$jwt) {
			return ['success' => false];
		}

		$response = wp_remote_post('https://api.cdp.coinbase.com' . $path, [
			'headers' => [
				'Content-Type'  => 'application/json',
				'Authorization' => 'Bearer ' . $jwt,
			],
			'body'    => wp_json_encode([
				'x402Version'         => 2,
				'paymentPayload'      => $payment_payload,
				'paymentRequirements' => $requirements,
			]),
			'timeout' => 15,
		]);

		if (is_wp_error($response)) {
			return ['success' => false];
		}

		$result = json_decode(wp_remote_retrieve_body($response), true);
		return is_array($result) ? $result : ['success' => false];
	}

	/**
	 * Generate CDP EdDSA JWT for API authentication.
	 *
	 * CDP Secret API keys use Ed25519 (EdDSA). The privateKey field in the JSON
	 * is a base64-encoded 64-byte Ed25519 signing key (seed || public key).
	 *
	 * @see https://docs.cdp.coinbase.com/api-reference/authentication
	 * @return string JWT on success, empty string on failure.
	 */
	private function generate_cdp_jwt(string $key_id, string $priv_key_b64, string $method, string $path): string {
		$key_bytes = base64_decode($priv_key_b64, true);
		if ($key_bytes === false || strlen($key_bytes) !== 64) {
			error_log('Baskerville generate_cdp_jwt: invalid key — expected 64-byte base64 Ed25519 key, got ' . strlen((string) $key_bytes) . ' bytes');
			return '';
		}

		$header = $this->core->b64u_enc((string) wp_json_encode([
			'alg'   => 'EdDSA',
			'typ'   => 'JWT',
			'kid'   => $key_id,
			'nonce' => bin2hex(random_bytes(16)),
		]));

		$now = time();
		$payload = $this->core->b64u_enc((string) wp_json_encode([
			'sub' => $key_id,
			'iss' => 'cdp',
			'nbf' => $now,
			'exp' => $now + 120,
			'uri' => $method . ' api.cdp.coinbase.com' . $path,
		]));

		$signing_input = $header . '.' . $payload;

		$signature = sodium_crypto_sign_detached($signing_input, $key_bytes);

		return $signing_input . '.' . $this->core->b64u_enc($signature);
	}

	// -------------------------------------------------------------------------
	// Grant helpers
	// -------------------------------------------------------------------------

	/**
	 * Set baskerville_grant cookie after successful payment.
	 */
	private function set_grant_cookie(string $token, string $canonical_url, int $ttl): void {
		setcookie('baskerville_grant', $token, [
			'expires'  => time() + $ttl,
			'path'     => wp_parse_url($canonical_url, PHP_URL_PATH) ?: '/',
			'secure'   => is_ssl(),
			'httponly' => true,
			'samesite' => 'Lax',
		]);
	}

	/**
	 * Extract BV1 grant token from Authorization header, query param, or cookie.
	 */
	private function get_grant_token(): ?string {
		// 1. Authorization: Bearer header
		$auth = isset($_SERVER['HTTP_AUTHORIZATION'])
			? sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']))
			: '';

		if (!$auth && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
			$auth = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
		}

		if ($auth && stripos($auth, 'Bearer ') === 0) {
			$token = trim(substr($auth, 7));
			if (strpos($token, 'BV1.') === 0) {
				return $token;
			}
		}

		// 2. Query parameter ?grant=BV1.xxx
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended
		if (isset($_GET['grant'])) {
			// phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$token = sanitize_text_field(wp_unslash($_GET['grant']));
			if (strpos($token, 'BV1.') === 0) {
				return $token;
			}
		}

		// 3. Cookie fallback
		if (isset($_COOKIE['baskerville_grant'])) {
			$token = sanitize_text_field(wp_unslash($_COOKIE['baskerville_grant']));
			if (strpos($token, 'BV1.') === 0) {
				return $token;
			}
		}

		return null;
	}

	// -------------------------------------------------------------------------
	// Shared helpers
	// -------------------------------------------------------------------------

	private function path_matches(string $path, array $options): bool {
		$patterns_raw = $options['pay_protected_paths'] ?? '/*';
		$lines = array_filter(array_map('trim', explode("\n", $patterns_raw)));

		if (empty($lines)) {
			return true;
		}

		foreach ($lines as $pattern) {
			if (fnmatch($pattern, $path)) {
				return true;
			}
		}

		return false;
	}

	private function get_ai_score(): int {
		$headers = [
			'user_agent'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
			'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
			'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
			'accept_encoding' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')),
			'connection'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_CONNECTION'] ?? '')),
			'remote_addr'     => sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')),
		];

		$evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
		$score      = (int) ($evaluation['score'] ?? 0);

		$fp_data = $this->core->read_fp_cookie();
		if ($fp_data !== null) {
			$score = max($score, (int) ($fp_data['sc'] ?? 0));
		}

		return $score;
	}

	private function canonical_url(): string {
		$scheme = (is_ssl() || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'))
			? 'https' : 'http';
		$host = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'] ?? 'localhost'));
		$uri  = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
		$path = wp_parse_url($uri, PHP_URL_PATH) ?: '/';

		return $scheme . '://' . $host . $path;
	}
}
