<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Pay-per-crawl policy engine.
 *
 * Hooked at template_redirect priority 1 (after log_page_visit at 0).
 * Checks grant -> checks ai_score -> returns 402 or allows.
 */
class Baskerville_Paywall {

	private Baskerville_Core $core;
	private Baskerville_Pay_Storage $storage;
	private Baskerville_Pay_Grant $grant;
	private Baskerville_Stats $stats;
	private Baskerville_AI_UA $aiua;

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

	/**
	 * Register the /eq402 test route (rewrite rule + query var + handler).
	 */
	public function init_eq402(): void {
		add_action('init', [$this, 'register_eq402_route']);
		add_filter('query_vars', [$this, 'add_eq402_query_var']);
		add_action('template_redirect', [$this, 'handle_eq402'], -1);
	}

	/**
	 * Add baskerville_eq402 to allowed query vars.
	 */
	public function add_eq402_query_var(array $vars): array {
		$vars[] = 'baskerville_eq402';
		return $vars;
	}

	/**
	 * Register rewrite rule: /eq402 → index.php?baskerville_eq402=1
	 */
	public function register_eq402_route(): void {
		add_rewrite_rule(
			'^eq402/?$',
			'index.php?baskerville_eq402=1',
			'top'
		);
	}

	/**
	 * Handle /eq402 requests — always behind paywall (no ai_score check).
	 * Runs at template_redirect priority -1 (before check_paywall at 1).
	 */
	public function handle_eq402(): void {
		if (!get_query_var('baskerville_eq402')) {
			return;
		}

		// Prevent caching plugins (WP-Super-Cache, etc.) from caching this page
		if (!defined('DONOTCACHEPAGE')) {
			define('DONOTCACHEPAGE', true);
		}

		$options = get_option('baskerville_settings', []);

		// Quick exits — pay must be enabled and in test or enforce mode
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

		// Check grant token (Authorization header, ?grant= query param, or cookie)
		$grant_token = $this->get_grant_token();
		if ($grant_token) {
			$payload = $this->grant->validate($grant_token, $canonical_url, $method);
			if ($payload !== null) {
				$this->render_eq402_success($payload, $options);
				exit;
			}
			// Debug: grant was present but invalid
			if (!headers_sent()) {
				header('X-Eq402-Debug-Canonical: ' . $canonical_url);
				header('X-Eq402-Debug-Has-Auth: true');
				header('X-Eq402-Debug-Token-Prefix: ' . substr($grant_token, 0, 30));
			}
		} else {
			if (!headers_sent()) {
				header('X-Eq402-Debug-Canonical: ' . $canonical_url);
				header('X-Eq402-Debug-Has-Auth: false');
			}
		}

		// Always send 402 — no ai_score check
		$this->send_402($canonical_url, 100, $options);
		exit;
	}

	/**
	 * Render the /eq402 congratulations page after successful payment.
	 */
	private function render_eq402_success(array $grant_payload, array $options): void {
		$amount   = $options['pay_price'] ?? '0.10';
		$currency = $options['pay_currency'] ?? 'USDC';
		$ttl      = (int) ($options['pay_grant_ttl'] ?? 900);
		$exp      = (int) ($grant_payload['exp'] ?? 0);
		$url      = $grant_payload['url'] ?? '';

		// Reconstruct token prefix for display (truncated)
		$req_id = $grant_payload['req_id'] ?? '';

		status_header(200);
		nocache_headers();
		header('Content-Type: text/html; charset=utf-8');

		$expires_at = gmdate('c', $exp);
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
		dd { margin-left: 20px; }
	</style>
</head>
<body>
	<h1>Congratulations!</h1>
	<p>You successfully paid to access this page via the Baskerville x402 paywall.</p>
	<dl>
		<dt>Amount paid</dt>
		<dd><?php echo esc_html($amount . ' ' . $currency); ?></dd>
		<dt>Grant TTL</dt>
		<dd><?php echo esc_html($ttl); ?> seconds</dd>
		<dt>Expires at</dt>
		<dd><?php echo esc_html($expires_at); ?></dd>
		<dt>Request ID</dt>
		<dd><?php echo esc_html($req_id); ?></dd>
		<dt>Canonical URL</dt>
		<dd><?php echo esc_html($url); ?></dd>
	</dl>
</body>
</html>
		<?php
	}

	/**
	 * Main paywall check — hooked to template_redirect at priority 1.
	 */
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

		// 2. Check path against protected_paths
		$uri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
		$path = wp_parse_url($uri, PHP_URL_PATH) ?: '/';

		if (!$this->path_matches($path, $options)) {
			return;
		}

		// 3. Check grant token (Authorization header, ?grant= query param, or cookie)
		$canonical_url = $this->canonical_url();
		$grant_token   = $this->get_grant_token();

		if ($grant_token) {
			$payload = $this->grant->validate($grant_token, $canonical_url, $method);
			if ($payload !== null) {
				return; // Valid grant — allow access
			}
		}

		// 4. Get ai_score
		$ai_score = $this->get_ai_score();

		// 5. Check threshold
		$threshold = (int) ($options['pay_ai_threshold'] ?? 70);
		if ($ai_score < $threshold) {
			return;
		}

		// 6. Observe mode — add header but don't block
		if ($pay_mode === 'observe') {
			if (!headers_sent()) {
				header('Baskerville-Paywall: would-402');
			}
			return;
		}

		// 7. Enforce mode — generate challenge and return 402
		if ($pay_mode === 'enforce') {
			$this->send_402($canonical_url, $ai_score, $options);
			exit;
		}
	}

	/**
	 * Check if request path matches any protected path pattern.
	 */
	private function path_matches(string $path, array $options): bool {
		$patterns_raw = $options['pay_protected_paths'] ?? '/*';
		$lines = array_filter(array_map('trim', explode("\n", $patterns_raw)));

		if (empty($lines)) {
			return true; // No patterns = match all
		}

		foreach ($lines as $pattern) {
			if (fnmatch($pattern, $path)) {
				return true;
			}
		}

		return false;
	}

	/**
	 * Extract grant token from Authorization header, query param, or cookie.
	 *
	 * Checks in order:
	 * 1. Authorization: Bearer BV1.xxx header
	 * 2. ?grant=BV1.xxx query parameter (CDN-friendly: unique URL bypasses cache)
	 * 3. baskerville_grant cookie (set by verify endpoint)
	 */
	private function get_grant_token(): ?string {
		// 1. Authorization: Bearer header
		$auth = isset($_SERVER['HTTP_AUTHORIZATION'])
			? sanitize_text_field(wp_unslash($_SERVER['HTTP_AUTHORIZATION']))
			: '';

		// Fallback for CGI/FastCGI
		if (!$auth && isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
			$auth = sanitize_text_field(wp_unslash($_SERVER['REDIRECT_HTTP_AUTHORIZATION']));
		}

		if ($auth && stripos($auth, 'Bearer ') === 0) {
			$token = trim(substr($auth, 7));
			if (strpos($token, 'BV1.') === 0) {
				return $token;
			}
		}

		// 2. Query parameter ?grant=BV1.xxx (CDN cache-bust)
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

	/**
	 * Extract Bearer token from Authorization header.
	 *
	 * @deprecated Use get_grant_token() instead.
	 */
	private function get_auth_header(): ?string {
		return $this->get_grant_token();
	}

	/**
	 * Compute AI score for the current request.
	 */
	private function get_ai_score(): int {
		$headers = [
			'user_agent'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
			'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
			'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
			'accept_encoding' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_ENCODING'] ?? '')),
			'connection'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_CONNECTION'] ?? '')),
			'remote_addr'     => sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')),
		];

		// Score from server-side headers (no JS fingerprint)
		$evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
		$score = (int) ($evaluation['score'] ?? 0);

		// Also check if there's a FP cookie score (take max)
		$fp_data = $this->core->read_fp_cookie();
		if ($fp_data !== null) {
			$fp_score = (int) ($fp_data['sc'] ?? 0);
			$score = max($score, $fp_score);
		}

		return $score;
	}

	/**
	 * Build the canonical URL for the current request.
	 */
	private function canonical_url(): string {
		$scheme = (is_ssl() || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https'))
			? 'https' : 'http';
		$host = sanitize_text_field(wp_unslash($_SERVER['HTTP_HOST'] ?? 'localhost'));
		$uri  = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? '/'));
		$path = wp_parse_url($uri, PHP_URL_PATH) ?: '/';

		return $scheme . '://' . $host . $path;
	}

	/**
	 * Generate 402 response with challenge.
	 */
	private function send_402(string $canonical_url, int $ai_score, array $options): void {
		$nonce     = $this->core->b64u_enc(random_bytes(16));
		$day       = wp_date('Y-m-d');
		$origin    = home_url();
		$req_id    = $this->core->b64u_enc(
			hash('sha256', $origin . '|' . $canonical_url . '|' . $day . '|' . $nonce, true)
		);

		$price           = $options['pay_price'] ?? '0.10';
		$currency        = $options['pay_currency'] ?? 'USDC';
		$network         = $options['pay_network'] ?? 'polygon';
		$wallet          = $options['pay_wallet_address'] ?? '';
		$asset_type      = $options['pay_asset_type'] ?? 'erc20';
		$token_contract  = $options['pay_token_contract'] ?? '';
		$token_decimals  = (int) ($options['pay_token_decimals'] ?? 6);
		$grant_ttl       = (int) ($options['pay_grant_ttl'] ?? 900);
		$ip              = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));

		// Store challenge
		$this->storage->insert_challenge([
			'req_id'         => $req_id,
			'canonical_url'  => $canonical_url,
			'price'          => $price,
			'currency'       => $currency,
			'network'        => $network,
			'wallet_address' => $wallet,
			'asset_type'     => $asset_type,
			'token_contract' => $token_contract,
			'token_decimals' => $token_decimals,
			'ai_score'       => $ai_score,
			'ip'             => $ip,
			'nonce'          => $nonce,
		]);

		// Build response
		$proof_endpoint = rest_url('baskerville/v1/payments/verify');

		$body = [
			'error'            => 'payment_required',
			'req_id'           => $req_id,
			'amount'           => $price,
			'currency'         => $currency,
			'network'          => $network,
			'wallet'           => $wallet,
			'asset_type'       => $asset_type,
			'proof_endpoint'   => $proof_endpoint,
			'grant_ttl_seconds' => $grant_ttl,
		];

		if ($asset_type === 'erc20' && $token_contract) {
			$body['token_contract'] = $token_contract;
			$body['token_decimals'] = $token_decimals;
		}

		// Send headers — no-store is stronger than nocache_headers() for CDN bypass
		status_header(402);
		nocache_headers();
		header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0', true);
		header('Vary: Authorization, Cookie', false);
		header('Content-Type: application/json');
		header('Baskerville-Pay: required');
		header('Baskerville-Req-Id: ' . $req_id);
		header('Baskerville-Price: ' . $price);
		header('Baskerville-Currency: ' . $currency);
		header('Baskerville-Network: ' . $network);
		header('Baskerville-Wallet: ' . $wallet);
		header('Baskerville-Asset-Type: ' . $asset_type);
		if ($asset_type === 'erc20' && $token_contract) {
			header('Baskerville-Token-Contract: ' . $token_contract);
		}
		header('Baskerville-Proof-Endpoint: ' . $proof_endpoint);
		header('Baskerville-Grant-TTL: ' . $grant_ttl);
		header('Baskerville-Reason: ai_score=' . $ai_score . ';policy=paywall');

		echo wp_json_encode($body);
	}
}
