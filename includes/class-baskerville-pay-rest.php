<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * REST endpoint: POST /baskerville/v1/payments/verify
 */
class Baskerville_Pay_REST {

	private Baskerville_Core $core;
	private Baskerville_Pay_Storage $storage;
	private Baskerville_Pay_Grant $grant;

	public function __construct(
		Baskerville_Core $core,
		Baskerville_Pay_Storage $storage,
		Baskerville_Pay_Grant $grant
	) {
		$this->core    = $core;
		$this->storage = $storage;
		$this->grant   = $grant;
	}

	/**
	 * Register REST routes.
	 */
	public function register_routes(): void {
		register_rest_route('baskerville/v1', '/payments/verify', [
			'methods'             => WP_REST_Server::CREATABLE,
			'callback'            => [$this, 'handle_verify'],
			'permission_callback' => function () { return true; }, // public endpoint, rate-limited below
		]);
	}

	/**
	 * Handle POST /baskerville/v1/payments/verify
	 *
	 * @param WP_REST_Request $request
	 * @return WP_REST_Response
	 */
	public function handle_verify(WP_REST_Request $request): WP_REST_Response {
		$ip     = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
		$params = $request->get_json_params();

		$req_id  = sanitize_text_field($params['req_id'] ?? '');
		$tx_hash = sanitize_text_field($params['tx_hash'] ?? '');

		if (!$req_id || !$tx_hash) {
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'missing_params',
			], 400);
		}

		// 1. Rate limit: max 5 per minute per IP+req_id
		$rl_key = "pay_verify:{$ip}:{$req_id}";
		$count  = $this->core->fc_inc_in_window($rl_key, 60);
		if ($count > 5) {
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'rate_limited',
			], 429);
		}

		// 2. Look up challenge
		$challenge = $this->storage->get_challenge($req_id);
		if (!$challenge) {
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'not_found',
			], 404);
		}

		// 3. Check challenge not expired
		$options       = get_option('baskerville_settings', []);
		$challenge_ttl = (int) ($options['pay_challenge_ttl'] ?? 3600);
		$created_ts    = strtotime($challenge->created_at . ' UTC');

		if ($challenge->status === 'expired' || (time() - $created_ts) > $challenge_ttl) {
			$this->storage->update_challenge_status($req_id, 'expired');
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'expired',
			], 400);
		}

		// 4. Check tx_hash not already used
		if ($this->storage->receipt_exists($tx_hash)) {
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'already_used',
			], 400);
		}

		// 5. Run verifier
		$verifier = Baskerville_Pay_Verifier_Factory::create($options);
		try {
			$result = $verifier->verify($tx_hash, $challenge);
		} catch (\Throwable $e) {
			return new WP_REST_Response([
				'status' => 'error',
				'code'   => 'internal_server_error',
				'detail' => $e->getMessage(),
			], 500);
		}

		// 6. Handle result
		if ($result->status === 'confirmed') {
			// Store receipt
			$receipt_data = $result->receipt ?? [];
			$receipt_data['tx_hash'] = $tx_hash;
			$receipt_data['req_id']  = $req_id;
			$this->storage->insert_receipt($receipt_data);

			// Mark challenge paid
			$this->storage->update_challenge_status($req_id, 'paid');

			// Mint grant
			$grant_ttl = (int) ($options['pay_grant_ttl'] ?? 900);
			$grant_data = $this->grant->mint($req_id, $challenge->canonical_url, $grant_ttl);

			// Set grant cookie (browser/CDN-friendly fallback for Authorization header)
			$grant_token = $grant_data['grant'];
			$cookie_path = wp_parse_url($challenge->canonical_url, PHP_URL_PATH) ?: '/';
			setcookie('baskerville_grant', $grant_token, [
				'expires'  => time() + $grant_ttl,
				'path'     => $cookie_path,
				'secure'   => is_ssl(),
				'httponly' => true,
				'samesite' => 'Lax',
			]);

			// Build grant_url: canonical URL + ?grant= for CDN cache-bust
			$grant_url = $challenge->canonical_url
				. (strpos($challenge->canonical_url, '?') !== false ? '&' : '?')
				. 'grant=' . urlencode($grant_token);

			return new WP_REST_Response([
				'status'     => 'ok',
				'req_id'     => $req_id,
				'grant'      => $grant_token,
				'grant_url'  => $grant_url,
				'expires_at' => $grant_data['expires_at'],
			], 200);
		}

		if ($result->status === 'pending') {
			return new WP_REST_Response([
				'status' => 'pending',
				'code'   => $result->code,
			], 202);
		}

		// rejected
		$error_response = [
			'status' => 'error',
			'code'   => $result->code,
		];

		// Include error detail when available (helps debugging)
		if (!empty($verifier->last_error)) {
			$error_response['detail'] = $verifier->last_error;
		}

		return new WP_REST_Response($error_response, 400);
	}
}
