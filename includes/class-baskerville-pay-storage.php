<?php

if (!defined('ABSPATH')) {
	exit;
}

/**
 * Pay-per-crawl storage: challenges + receipts tables via dbDelta().
 */
class Baskerville_Pay_Storage {

	private Baskerville_Core $core;

	public function __construct(Baskerville_Core $core) {
		$this->core = $core;
	}

	/* ===== Table names ===== */

	private function challenges_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'baskerville_pay_challenges';
	}

	private function receipts_table(): string {
		global $wpdb;
		return $wpdb->prefix . 'baskerville_pay_receipts';
	}

	/* ===== Schema ===== */

	/**
	 * Create or upgrade pay tables. Called on plugin activation.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function create_tables(): void {
		global $wpdb;
		$charset = $wpdb->get_charset_collate();

		$challenges = $this->challenges_table();
		$receipts   = $this->receipts_table();

		$sql_challenges = "CREATE TABLE $challenges (
			req_id varchar(64) NOT NULL,
			canonical_url text NOT NULL,
			price varchar(32) NOT NULL,
			currency varchar(16) NOT NULL,
			network varchar(32) NOT NULL,
			wallet_address varchar(64) NOT NULL,
			asset_type varchar(16) NOT NULL DEFAULT 'native',
			token_contract varchar(64) NOT NULL DEFAULT '',
			token_decimals smallint NOT NULL DEFAULT 18,
			ai_score smallint NOT NULL DEFAULT 0,
			ip varchar(45) NOT NULL DEFAULT '',
			nonce varchar(44) NOT NULL DEFAULT '',
			created_at datetime NOT NULL,
			status varchar(16) NOT NULL DEFAULT 'new',
			PRIMARY KEY  (req_id),
			KEY status (status),
			KEY created_at (created_at),
			KEY ip (ip)
		) $charset;";

		$sql_receipts = "CREATE TABLE $receipts (
			tx_hash varchar(128) NOT NULL,
			req_id varchar(64) NOT NULL,
			amount varchar(32) NOT NULL DEFAULT '0',
			currency varchar(16) NOT NULL DEFAULT '',
			network varchar(32) NOT NULL DEFAULT '',
			wallet_address varchar(64) NOT NULL DEFAULT '',
			asset_type varchar(16) NOT NULL DEFAULT 'native',
			token_contract varchar(64) NOT NULL DEFAULT '',
			confirmed_at datetime NOT NULL,
			raw_json longtext NOT NULL,
			PRIMARY KEY  (tx_hash),
			KEY req_id (req_id)
		) $charset;";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta($sql_challenges);
		dbDelta($sql_receipts);
	}

	/* ===== Challenge CRUD ===== */

	/**
	 * Insert a new challenge record.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function insert_challenge(array $data): bool {
		global $wpdb;
		return (bool) $wpdb->insert($this->challenges_table(), [
			'req_id'          => $data['req_id'],
			'canonical_url'   => $data['canonical_url'],
			'price'           => $data['price'],
			'currency'        => $data['currency'],
			'network'         => $data['network'],
			'wallet_address'  => $data['wallet_address'],
			'asset_type'      => $data['asset_type'] ?? 'native',
			'token_contract'  => $data['token_contract'] ?? '',
			'token_decimals'  => $data['token_decimals'] ?? 18,
			'ai_score'        => $data['ai_score'] ?? 0,
			'ip'              => $data['ip'] ?? '',
			'nonce'           => $data['nonce'] ?? '',
			'created_at'      => gmdate('Y-m-d H:i:s'),
			'status'          => 'new',
		]);
	}

	/**
	 * Fetch a challenge by req_id.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function get_challenge(string $req_id): ?object {
		global $wpdb;
		$table = $this->challenges_table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$row = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table WHERE req_id = %s", $req_id));
		return $row ?: null;
	}

	/**
	 * Update challenge status (new -> paid | expired).
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function update_challenge_status(string $req_id, string $status): bool {
		global $wpdb;
		return (bool) $wpdb->update(
			$this->challenges_table(),
			['status' => $status],
			['req_id' => $req_id],
			['%s'],
			['%s']
		);
	}

	/* ===== Receipt CRUD ===== */

	/**
	 * Insert a receipt record.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function insert_receipt(array $data): bool {
		global $wpdb;
		return (bool) $wpdb->insert($this->receipts_table(), [
			'tx_hash'        => $data['tx_hash'],
			'req_id'         => $data['req_id'],
			'amount'         => $data['amount'] ?? '0',
			'currency'       => $data['currency'] ?? '',
			'network'        => $data['network'] ?? '',
			'wallet_address' => $data['wallet_address'] ?? '',
			'asset_type'     => $data['asset_type'] ?? 'native',
			'token_contract' => $data['token_contract'] ?? '',
			'confirmed_at'   => gmdate('Y-m-d H:i:s'),
			'raw_json'       => $data['raw_json'] ?? '{}',
		]);
	}

	/**
	 * Check if a tx_hash has already been used.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function receipt_exists(string $tx_hash): bool {
		global $wpdb;
		$table = $this->receipts_table();
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$count = (int) $wpdb->get_var($wpdb->prepare("SELECT COUNT(*) FROM $table WHERE tx_hash = %s", $tx_hash));
		return $count > 0;
	}

	/* ===== Maintenance ===== */

	/**
	 * Expire old challenges and delete them.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function cleanup_expired(int $ttl_seconds = 3600): int {
		global $wpdb;
		$table = $this->challenges_table();
		$cutoff = gmdate('Y-m-d H:i:s', time() - $ttl_seconds);

		// Mark as expired
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$wpdb->query($wpdb->prepare(
			"UPDATE $table SET status = 'expired' WHERE status = 'new' AND created_at < %s",
			$cutoff
		));

		// Delete very old records (> 7 days)
		$old_cutoff = gmdate('Y-m-d H:i:s', time() - 7 * 86400);
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
		$deleted = (int) $wpdb->query($wpdb->prepare(
			"DELETE FROM $table WHERE created_at < %s",
			$old_cutoff
		));

		return $deleted;
	}
}
