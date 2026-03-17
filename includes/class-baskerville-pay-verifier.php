<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Value object returned by verifiers.
 */
class Baskerville_Pay_Verify_Result {

	/** @var string confirmed|pending|rejected */
	public string $status;

	/** @var string Machine-readable code (e.g. 'ok', 'unconfirmed', 'wrong_recipient') */
	public string $code;

	/** @var array|null Receipt data on confirmation */
	public ?array $receipt;

	public function __construct(string $status, string $code, ?array $receipt = null) {
		$this->status  = $status;
		$this->code    = $code;
		$this->receipt = $receipt;
	}

	public static function confirmed(array $receipt): self {
		return new self('confirmed', 'ok', $receipt);
	}

	public static function pending(string $code = 'unconfirmed'): self {
		return new self('pending', $code);
	}

	public static function rejected(string $code): self {
		return new self('rejected', $code);
	}
}

/**
 * Stub verifier: accepts tx_hash starting with "demo_" and returns confirmed.
 */
class Baskerville_Pay_Verifier_Stub {

	/**
	 * Verify a transaction (stub mode).
	 *
	 * @param string $tx_hash  The transaction hash.
	 * @param object $challenge The challenge record from DB.
	 * @return Baskerville_Pay_Verify_Result
	 */
	public function verify(string $tx_hash, object $challenge): Baskerville_Pay_Verify_Result {
		if (strpos($tx_hash, 'demo_') !== 0) {
			return Baskerville_Pay_Verify_Result::rejected('invalid_tx');
		}

		return Baskerville_Pay_Verify_Result::confirmed([
			'tx_hash'        => $tx_hash,
			'amount'         => $challenge->price,
			'currency'       => $challenge->currency,
			'network'        => $challenge->network,
			'wallet_address' => $challenge->wallet_address,
			'asset_type'     => $challenge->asset_type,
			'token_contract' => $challenge->token_contract,
			'raw_json'       => wp_json_encode(['stub' => true, 'tx_hash' => $tx_hash]),
		]);
	}
}

/**
 * Polling verifier: verifies transactions via Polygon/EVM JSON-RPC.
 */
class Baskerville_Pay_Verifier_Polling {

	private string $rpc_url;
	private int $min_confirmations;
	private int $challenge_ttl;

	/** ERC-20 Transfer event topic0 */
	const TRANSFER_TOPIC = '0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef';

	public function __construct(string $rpc_url, int $min_confirmations = 5, int $challenge_ttl = 3600) {
		$this->rpc_url           = $rpc_url;
		$this->min_confirmations = $min_confirmations;
		$this->challenge_ttl     = $challenge_ttl;
	}

	/** @var string|null Last RPC error message for debugging */
	public ?string $last_error = null;

	/**
	 * Verify a transaction via JSON-RPC.
	 *
	 * @param string $tx_hash  The transaction hash (0x-prefixed).
	 * @param object $challenge The challenge record from DB.
	 * @return Baskerville_Pay_Verify_Result
	 */
	public function verify(string $tx_hash, object $challenge): Baskerville_Pay_Verify_Result {
		// Validate tx_hash format
		if (!preg_match('/^0x[0-9a-fA-F]{64}$/', $tx_hash)) {
			return Baskerville_Pay_Verify_Result::rejected('invalid_tx');
		}

		// 1. Get transaction receipt
		$receipt = $this->rpc_call('eth_getTransactionReceipt', [$tx_hash]);
		if ($receipt === null) {
			return Baskerville_Pay_Verify_Result::pending('unconfirmed');
		}
		if (is_wp_error($receipt)) {
			$this->last_error = $receipt->get_error_message();
			return Baskerville_Pay_Verify_Result::rejected('provider_error');
		}

		// Check tx was successful (status 0x1)
		$tx_status = $receipt['status'] ?? '0x0';
		if ($tx_status !== '0x1') {
			return Baskerville_Pay_Verify_Result::rejected('invalid_tx');
		}

		// 2. Check confirmations
		$tx_block = hexdec($receipt['blockNumber'] ?? '0x0');
		$current_block_hex = $this->rpc_call('eth_blockNumber', []);
		if (is_wp_error($current_block_hex) || $current_block_hex === null) {
			return Baskerville_Pay_Verify_Result::rejected('provider_error');
		}
		$current_block = hexdec($current_block_hex);
		$confirmations = $current_block - $tx_block;

		if ($confirmations < $this->min_confirmations) {
			return Baskerville_Pay_Verify_Result::pending('unconfirmed');
		}

		// 3. Verify payment details based on asset type
		$wallet = strtolower($challenge->wallet_address);

		if ($challenge->asset_type === 'native') {
			return $this->verify_native($tx_hash, $challenge, $wallet);
		}

		return $this->verify_erc20($receipt, $challenge, $wallet);
	}

	/**
	 * Verify native currency transfer (e.g. MATIC/POL).
	 */
	private function verify_native(string $tx_hash, object $challenge, string $wallet): Baskerville_Pay_Verify_Result {
		$tx = $this->rpc_call('eth_getTransactionByHash', [$tx_hash]);
		if ($tx === null || is_wp_error($tx)) {
			return Baskerville_Pay_Verify_Result::rejected('provider_error');
		}

		// Check recipient
		$to = strtolower($tx['to'] ?? '');
		if ($to !== $wallet) {
			return Baskerville_Pay_Verify_Result::rejected('wrong_recipient');
		}

		// Check value (in wei)
		$value_wei = self::hex_to_decimal($tx['value'] ?? '0x0');
		$price_wei = self::mul_by_pow10($challenge->price, 18);
		if (self::str_cmp($value_wei, $price_wei) < 0) {
			return Baskerville_Pay_Verify_Result::rejected('underpaid');
		}

		// Check timestamp within challenge TTL
		if (!$this->check_tx_timestamp($tx, $challenge)) {
			return Baskerville_Pay_Verify_Result::rejected('expired');
		}

		return Baskerville_Pay_Verify_Result::confirmed([
			'tx_hash'        => $tx_hash,
			'amount'         => $challenge->price,
			'currency'       => $challenge->currency,
			'network'        => $challenge->network,
			'wallet_address' => $challenge->wallet_address,
			'asset_type'     => 'native',
			'token_contract' => '',
			'raw_json'       => wp_json_encode($tx),
		]);
	}

	/**
	 * Verify ERC-20 token transfer via Transfer event log.
	 */
	private function verify_erc20(array $receipt, object $challenge, string $wallet): Baskerville_Pay_Verify_Result {
		$token_contract = strtolower($challenge->token_contract);
		$decimals       = (int) $challenge->token_decimals;
		$price_smallest = self::mul_by_pow10($challenge->price, $decimals);

		$logs = $receipt['logs'] ?? [];
		foreach ($logs as $log) {
			$address = strtolower($log['address'] ?? '');
			$topics  = $log['topics'] ?? [];

			// Must be Transfer event from the correct token contract
			if ($address !== $token_contract) {
				continue;
			}
			if (count($topics) < 3 || $topics[0] !== self::TRANSFER_TOPIC) {
				continue;
			}

			// topics[2] = "to" address (32-byte zero-padded)
			$to = '0x' . substr($topics[2], -40);
			if (strtolower($to) !== $wallet) {
				continue;
			}

			// data = transfer amount (uint256)
			$amount_hex = $log['data'] ?? '0x0';
			$amount = self::hex_to_decimal($amount_hex);

			if (self::str_cmp($amount, $price_smallest) >= 0) {
				return Baskerville_Pay_Verify_Result::confirmed([
					'tx_hash'        => $receipt['transactionHash'] ?? '',
					'amount'         => $challenge->price,
					'currency'       => $challenge->currency,
					'network'        => $challenge->network,
					'wallet_address' => $challenge->wallet_address,
					'asset_type'     => 'erc20',
					'token_contract' => $challenge->token_contract,
					'raw_json'       => wp_json_encode($receipt),
				]);
			}

			$this->last_error = 'paid=' . $amount . ' expected=' . $price_smallest . ' hex=' . $amount_hex;
			return Baskerville_Pay_Verify_Result::rejected('underpaid');
		}

		return Baskerville_Pay_Verify_Result::rejected('wrong_asset');
	}

	/**
	 * Check that the transaction's block timestamp is within challenge TTL.
	 */
	private function check_tx_timestamp(array $tx, object $challenge): bool {
		$block_hex = $tx['blockNumber'] ?? null;
		if (!$block_hex) {
			return true; // Can't verify, allow it
		}

		$block = $this->rpc_call('eth_getBlockByNumber', [$block_hex, false]);
		if ($block === null || is_wp_error($block)) {
			return true; // Can't verify, allow it
		}

		$block_ts   = hexdec($block['timestamp'] ?? '0x0');
		$created_at = strtotime($challenge->created_at . ' UTC');
		$diff       = abs($block_ts - $created_at);

		return $diff <= $this->challenge_ttl;
	}

	/**
	 * Make a JSON-RPC call to the configured node.
	 *
	 * @param string $method RPC method name.
	 * @param array  $params RPC params.
	 * @return mixed Result value, null if not found, or WP_Error on failure.
	 */
	private function rpc_call(string $method, array $params) {
		static $id = 0;

		// Try primary RPC, then fallbacks
		$urls = [$this->rpc_url];
		$fallbacks = Baskerville_Pay_Verifier_Factory::FALLBACK_RPC_URLS[$this->network_key()] ?? [];
		foreach ($fallbacks as $fb) {
			if ($fb !== $this->rpc_url) {
				$urls[] = $fb;
			}
		}

		$last_error = null;
		foreach ($urls as $url) {
			$id++;
			$body = wp_json_encode([
				'jsonrpc' => '2.0',
				'method'  => $method,
				'params'  => $params,
				'id'      => $id,
			]);

			$response = wp_remote_post($url, [
				'headers' => ['Content-Type' => 'application/json'],
				'body'    => $body,
				'timeout' => 15,
			]);

			if (is_wp_error($response)) {
				$last_error = $response;
				continue;
			}

			$code = wp_remote_retrieve_response_code($response);
			if ($code !== 200) {
				$last_error = new WP_Error('rpc_http_error', 'RPC HTTP ' . $code . ' from ' . $url);
				continue;
			}

			$decoded = json_decode(wp_remote_retrieve_body($response), true);
			if (!is_array($decoded)) {
				$last_error = new WP_Error('rpc_decode_error', 'Bad JSON from ' . $url);
				continue;
			}

			if (isset($decoded['error'])) {
				$last_error = new WP_Error('rpc_error', ($decoded['error']['message'] ?? 'RPC error') . ' from ' . $url);
				continue;
			}

			return $decoded['result'] ?? null;
		}

		return $last_error ?? new WP_Error('rpc_all_failed', 'All RPC endpoints failed');
	}

	/**
	 * Derive network key from the RPC URL for fallback lookup.
	 */
	private function network_key(): string {
		if (strpos($this->rpc_url, 'amoy') !== false) {
			return 'polygon-amoy';
		}
		if (strpos($this->rpc_url, 'polygon') !== false || strpos($this->rpc_url, 'matic') !== false) {
			return 'polygon';
		}
		if (strpos($this->rpc_url, 'eth') !== false || strpos($this->rpc_url, 'llama') !== false) {
			return 'ethereum';
		}
		return 'polygon'; // default
	}

	/**
	 * Convert a hex string to decimal string (for large numbers).
	 * Works with bcmath, gmp, or pure PHP.
	 */
	private static function hex_to_decimal(string $hex): string {
		$hex = ltrim($hex, '0x');
		$hex = ltrim($hex, '0');
		if ($hex === '') {
			return '0';
		}

		if (function_exists('gmp_init')) {
			return gmp_strval(gmp_init($hex, 16));
		}

		if (function_exists('bcmul')) {
			$dec = '0';
			for ($i = 0; $i < strlen($hex); $i++) {
				$dec = bcadd(bcmul($dec, '16'), (string) hexdec($hex[$i]));
			}
			return $dec;
		}

		// Fallback: only safe for values that fit in PHP int (up to ~9.2e18)
		return (string) hexdec($hex);
	}

	/**
	 * Multiply a decimal string (e.g. "0.10") by 10^exp to get smallest-unit integer string.
	 */
	private static function mul_by_pow10(string $value, int $exp): string {
		// Remove leading/trailing whitespace
		$value = trim($value);

		// Split on decimal point
		$parts = explode('.', $value, 2);
		$integer_part = $parts[0];
		$frac_part    = $parts[1] ?? '';

		// Pad or trim fractional part to exactly $exp digits
		if (strlen($frac_part) <= $exp) {
			$frac_part = str_pad($frac_part, $exp, '0');
		} else {
			// More decimals than exp — truncate (shouldn't happen with normal prices)
			$frac_part = substr($frac_part, 0, $exp);
		}

		$result = $integer_part . $frac_part;
		// Remove leading zeros but keep at least '0'
		$result = ltrim($result, '0') ?: '0';

		return $result;
	}

	/**
	 * Compare two numeric strings. Returns -1, 0, or 1.
	 */
	private static function str_cmp(string $a, string $b): int {
		// Remove leading zeros for fair comparison
		$a = ltrim($a, '0') ?: '0';
		$b = ltrim($b, '0') ?: '0';

		if (strlen($a) !== strlen($b)) {
			return strlen($a) <=> strlen($b);
		}

		return strcmp($a, $b);
	}
}

/**
 * Factory to create the appropriate verifier based on settings.
 */
class Baskerville_Pay_Verifier_Factory {

	/** Default RPC URLs by network */
	const DEFAULT_RPC_URLS = [
		'polygon'       => 'https://polygon-rpc.com',
		'polygon-amoy'  => 'https://rpc-amoy.polygon.technology',
		'ethereum'      => 'https://eth.llamarpc.com',
	];

	/** Fallback RPC URLs tried when the primary fails */
	const FALLBACK_RPC_URLS = [
		'polygon'       => [
			'https://polygon-rpc.com',
			'https://rpc.ankr.com/polygon',
			'https://polygon.llamarpc.com',
		],
		'polygon-amoy'  => [
			'https://rpc-amoy.polygon.technology',
			'https://rpc.ankr.com/polygon_amoy',
		],
		'ethereum'      => [
			'https://eth.llamarpc.com',
			'https://rpc.ankr.com/eth',
		],
	];

	/**
	 * Create a verifier instance based on plugin settings.
	 *
	 * @param array $options Plugin settings (baskerville_settings).
	 * @return Baskerville_Pay_Verifier_Stub|Baskerville_Pay_Verifier_Polling
	 */
	public static function create(array $options) {
		$type = $options['pay_verifier_type'] ?? 'stub';

		if ($type === 'polling') {
			$network  = $options['pay_network'] ?? 'polygon';
			$provider = $options['pay_provider'] ?? '';
			$api_key  = $options['pay_api_key'] ?? '';

			// Build RPC URL
			if ($provider && $api_key) {
				$rpc_url = self::provider_rpc_url($provider, $network, $api_key);
			} else {
				$rpc_url = self::DEFAULT_RPC_URLS[$network] ?? self::DEFAULT_RPC_URLS['polygon'];
			}

			$min_conf     = (int) ($options['pay_min_confirmations'] ?? 5);
			$challenge_ttl = (int) ($options['pay_challenge_ttl'] ?? 3600);

			return new Baskerville_Pay_Verifier_Polling($rpc_url, $min_conf, $challenge_ttl);
		}

		return new Baskerville_Pay_Verifier_Stub();
	}

	/**
	 * Build an RPC URL for a named provider.
	 */
	private static function provider_rpc_url(string $provider, string $network, string $api_key): string {
		$network_slug = ($network === 'polygon-amoy') ? 'polygon-amoy' : $network;

		switch ($provider) {
			case 'alchemy':
				$chain = ($network_slug === 'polygon-amoy') ? 'polygon-amoy' : 'polygon-mainnet';
				return "https://{$chain}.g.alchemy.com/v2/{$api_key}";

			case 'infura':
				$chain = ($network_slug === 'polygon-amoy') ? 'polygon-amoy' : 'polygon-mainnet';
				return "https://{$chain}.infura.io/v3/{$api_key}";

			case 'ankr':
				$chain = ($network_slug === 'polygon-amoy') ? 'polygon_amoy' : 'polygon';
				return "https://rpc.ankr.com/{$chain}/{$api_key}";

			default:
				return self::DEFAULT_RPC_URLS[$network] ?? self::DEFAULT_RPC_URLS['polygon'];
		}
	}
}
