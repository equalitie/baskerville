<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * BV1 grant tokens: mint and validate HMAC-signed access grants.
 *
 * Format: BV1.<b64url(payload_json)>.<b64url(hmac_sha256)>
 */
class Baskerville_Pay_Grant {

	private Baskerville_Core $core;

	public function __construct(Baskerville_Core $core) {
		$this->core = $core;
	}

	/**
	 * Mint a new BV1 grant token.
	 *
	 * @param string $req_id       Challenge request ID.
	 * @param string $canonical_url The canonical URL this grant covers.
	 * @param int    $ttl          Token lifetime in seconds.
	 * @return array{grant: string, expires_at: string}
	 */
	public function mint(string $req_id, string $canonical_url, int $ttl = 900): array {
		$now = time();
		$exp = $now + $ttl;

		$payload = [
			'v'      => 1,
			'iss'    => home_url(),
			'req_id' => $req_id,
			'url'    => $canonical_url,
			'm'      => ['GET', 'HEAD'],
			'iat'    => $now,
			'exp'    => $exp,
		];

		$payload_b64 = $this->core->b64u_enc(wp_json_encode($payload));
		$sig_input   = 'BV1.' . $payload_b64;
		$sig_bytes   = hash_hmac('sha256', $sig_input, $this->core->grant_secret(), true);
		$sig_b64     = $this->core->b64u_enc($sig_bytes);

		$grant = 'BV1.' . $payload_b64 . '.' . $sig_b64;

		return [
			'grant'      => $grant,
			'expires_at' => gmdate('c', $exp),
		];
	}

	/**
	 * Validate a BV1 grant token.
	 *
	 * @param string $token         The full BV1.xxx.sig token.
	 * @param string $canonical_url The canonical URL of the current request.
	 * @param string $method        The HTTP method (GET, HEAD, etc.).
	 * @return array|null Payload array on success, null on failure.
	 */
	public function validate(string $token, string $canonical_url, string $method = 'GET'): ?array {
		$parts = explode('.', $token, 3);
		if (count($parts) !== 3 || $parts[0] !== 'BV1') {
			return null;
		}

		$payload_b64 = $parts[1];
		$sig_b64     = $parts[2];

		// Verify signature
		$sig_input    = 'BV1.' . $payload_b64;
		$expected_sig = hash_hmac('sha256', $sig_input, $this->core->grant_secret(), true);
		$actual_sig   = $this->core->b64u_dec($sig_b64);

		if (!hash_equals($expected_sig, $actual_sig)) {
			return null;
		}

		// Decode payload
		$json = $this->core->b64u_dec($payload_b64);
		$payload = json_decode($json, true);
		if (!is_array($payload)) {
			return null;
		}

		// Check expiry
		$exp = (int) ($payload['exp'] ?? 0);
		if ($exp < time()) {
			return null;
		}

		// Check method
		$allowed_methods = $payload['m'] ?? [];
		if (!in_array(strtoupper($method), $allowed_methods, true)) {
			return null;
		}

		// Check URL
		$grant_url = $payload['url'] ?? '';
		if ($grant_url !== $canonical_url) {
			return null;
		}

		return $payload;
	}
}
