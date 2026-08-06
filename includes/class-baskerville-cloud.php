<?php
/**
 * Baskerville Cloud — LLM-powered incident analysis (Level 1: cluster/traffic analysis).
 *
 * Flow:
 *   1. WP Cron (every 5 min) calls maybe_analyze().
 *   2. Detects traffic spike OR decision spike vs baseline.
 *   3. Fire-and-forget POST to api.baskerville.ai/v1/analyze → receives job_id.
 *   4. Next cron run polls GET /v1/report/{job_id} until ready.
 *   5. Saves report to wp_baskerville_reports, applies action locally.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Baskerville_Cloud {

	const API_BASE          = 'https://api.baskerville.ai/v1';
	const OPTION_LICENSE    = 'baskerville_cloud_license_key';
	const OPTION_PENDING    = 'baskerville_cloud_pending_job';   // {job_id, submitted_at}
	const OPTION_LAST_SPIKE = 'baskerville_cloud_last_spike';    // unix timestamp

	// Spike thresholds
	const TRAFFIC_SPIKE_FACTOR   = 3.0;  // current bucket vs baseline
	const DECISIONS_SPIKE_FACTOR = 3.0;  // blocks/challenges spike
	const SPIKE_COOLDOWN_SEC     = 1800; // don't re-trigger within 30 min

	/** @var Baskerville_Stats */
	private $stats;

	public function __construct( Baskerville_Stats $stats ) {
		$this->stats = $stats;
	}

	// -------------------------------------------------------------------------
	// Main entry point (called by WP Cron every 5 min)
	// -------------------------------------------------------------------------

	public function maybe_analyze(): void {
		if ( ! $this->is_enabled() ) {
			return;
		}

		// First: poll for any pending job result.
		$this->poll_pending_job();

		// Then: check for new spike (respects cooldown).
		$last_spike = (int) get_option( self::OPTION_LAST_SPIKE, 0 );
		if ( time() - $last_spike < self::SPIKE_COOLDOWN_SEC ) {
			return;
		}

		// Don't submit a new job if one is already pending.
		if ( get_option( self::OPTION_PENDING ) ) {
			return;
		}

		$spike = $this->detect_spike();
		if ( ! $spike ) {
			return;
		}

		wpsec_log( "Baskerville Cloud: spike detected ({$spike['type']}, factor {$spike['factor']}x). Submitting analysis." );

		$payload  = $this->build_payload( $spike );
		$job_id   = $this->submit_analysis( $payload );

		if ( $job_id ) {
			update_option( self::OPTION_PENDING, [
				'job_id'       => $job_id,
				'submitted_at' => time(),
			] );
			update_option( self::OPTION_LAST_SPIKE, time() );
			wpsec_log( "Baskerville Cloud: job submitted, id={$job_id}" );
		}
	}

	// -------------------------------------------------------------------------
	// Spike detection
	// -------------------------------------------------------------------------

	/**
	 * Returns ['type' => 'traffic|decisions|both', 'factor' => float] or null.
	 */
	private function detect_spike(): ?array {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'baskerville_stats' );

		// 5-minute bucket counts for last 30 minutes (6 buckets).
		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$rows = $wpdb->get_results(
			"SELECT
				FLOOR(UNIX_TIMESTAMP(timestamp_utc) / 300) AS bucket,
				COUNT(*) AS total,
				SUM(CASE WHEN event_type='block' OR classification IN ('bad_bot','bot') THEN 1 ELSE 0 END) AS decisions
			 FROM {$table}
			 WHERE timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 MINUTE)
			   AND event_type IN ('page','fp','block')
			 GROUP BY bucket
			 ORDER BY bucket ASC",
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		if ( count( $rows ) < 3 ) {
			return null; // not enough data
		}

		// Last bucket is current (may be partial) — use second-to-last as "current".
		$last    = array_pop( $rows ); // discard partial bucket
		$current = array_pop( $rows );
		$baseline_rows = $rows; // remaining buckets = baseline

		if ( empty( $baseline_rows ) ) {
			return null;
		}

		$baseline_total     = array_sum( array_column( $baseline_rows, 'total' ) ) / count( $baseline_rows );
		$baseline_decisions = array_sum( array_column( $baseline_rows, 'decisions' ) ) / count( $baseline_rows );

		$traffic_factor   = $baseline_total > 0 ? (float) $current['total'] / $baseline_total : 0;
		$decisions_factor = $baseline_decisions > 0 ? (float) $current['decisions'] / $baseline_decisions : 0;

		$traffic_spike   = $traffic_factor   >= self::TRAFFIC_SPIKE_FACTOR;
		$decisions_spike = $decisions_factor >= self::DECISIONS_SPIKE_FACTOR;

		if ( ! $traffic_spike && ! $decisions_spike ) {
			return null;
		}

		if ( $traffic_spike && $decisions_spike ) {
			$type   = 'both';
			$factor = max( $traffic_factor, $decisions_factor );
		} elseif ( $traffic_spike ) {
			$type   = 'traffic';
			$factor = $traffic_factor;
		} else {
			$type   = 'decisions';
			$factor = $decisions_factor;
		}

		return [ 'type' => $type, 'factor' => round( $factor, 1 ) ];
	}

	// -------------------------------------------------------------------------
	// Payload builder
	// -------------------------------------------------------------------------

	private function build_payload( array $spike ): array {
		global $wpdb;
		$table  = esc_sql( $wpdb->prefix . 'baskerville_stats' );
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - 1800 ); // last 30 min

		// phpcs:disable WordPress.DB.DirectDatabaseQuery

		// 1. Timeline (5-min buckets)
		$timeline = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				DATE_FORMAT(FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(timestamp_utc)/300)*300), '%%Y-%%m-%%d %%H:%%i') AS bucket,
				COUNT(*) AS requests
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY bucket ORDER BY bucket ASC",
			$cutoff
		), ARRAY_A );

		// 2. Baseline window for ASN/country comparison (previous 24h, excluding last 30 min)
		$baseline_start = gmdate( 'Y-m-d H:i:s', time() - 86400 );
		$baseline_end   = gmdate( 'Y-m-d H:i:s', time() - 1800 );

		// 3. Top ASNs — attack vs normal
		$top_asns = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				COALESCE(NULLIF(asn,''),'Unknown') AS asn,
				ROUND(100 * SUM(CASE WHEN timestamp_utc >= %s THEN 1 ELSE 0 END) /
					NULLIF(SUM(CASE WHEN timestamp_utc >= %s THEN 1 ELSE 0 END), 0), 1) AS attack_pct,
				ROUND(100 * SUM(CASE WHEN timestamp_utc < %s AND timestamp_utc >= %s THEN 1 ELSE 0 END) /
					NULLIF(SUM(CASE WHEN timestamp_utc < %s AND timestamp_utc >= %s THEN 1 ELSE 0 END), 0), 1) AS normal_pct
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY asn
			 HAVING attack_pct IS NOT NULL
			 ORDER BY attack_pct DESC
			 LIMIT 10",
			$cutoff,      // attack window start
			$cutoff,      // attack total denominator
			$cutoff,      // normal window end
			$baseline_start, // normal window start
			$cutoff,      // normal total end
			$baseline_start, // normal total start
			$baseline_start  // WHERE clause
		), ARRAY_A );

		// 4. Top countries
		$top_countries = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				COALESCE(NULLIF(country_code,''),'XX') AS country,
				ROUND(100 * SUM(CASE WHEN timestamp_utc >= %s THEN 1 ELSE 0 END) /
					NULLIF(SUM(CASE WHEN timestamp_utc >= %s THEN 1 ELSE 0 END), 0), 1) AS attack_pct,
				ROUND(100 * SUM(CASE WHEN timestamp_utc < %s AND timestamp_utc >= %s THEN 1 ELSE 0 END) /
					NULLIF(SUM(CASE WHEN timestamp_utc < %s AND timestamp_utc >= %s THEN 1 ELSE 0 END), 0), 1) AS normal_pct
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY country_code
			 HAVING attack_pct IS NOT NULL
			 ORDER BY attack_pct DESC
			 LIMIT 10",
			$cutoff, $cutoff,
			$cutoff, $baseline_start,
			$cutoff, $baseline_start,
			$baseline_start
		), ARRAY_A );

		// 5. Top URLs
		$top_urls = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				SUBSTRING_INDEX(REPLACE(REPLACE(evaluation_json, '\\\\\"', ''), '\"', ''), 'request_uri', -1) AS url,
				COUNT(*) AS count
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY url ORDER BY count DESC LIMIT 10",
			$cutoff
		), ARRAY_A );

		// 6. UA distribution
		$ua_distribution = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent, COUNT(*) AS count
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY user_agent ORDER BY count DESC LIMIT 10",
			$cutoff
		), ARRAY_A );

		// 7. Unique IPs
		$unique_ips = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')",
			$cutoff
		) );

		// 8. Fingerprint signals (% of attack sessions with each anomaly)
		$fp_signals = $this->build_fingerprint_signals( $cutoff );

		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return [
			'license_key'          => (string) get_option( self::OPTION_LICENSE, '' ),
			'domain'               => parse_url( get_site_url(), PHP_URL_HOST ),
			'spike_type'           => $spike['type'],
			'spike_factor'         => $spike['factor'],
			'unique_ips'           => $unique_ips,
			'timeline'             => $timeline ?: [],
			'top_asns'             => $top_asns ?: [],
			'top_countries'        => $top_countries ?: [],
			'top_urls'             => array_map( function( $r ) {
				return [ 'url' => mb_substr( (string) $r['url'], 0, 200 ), 'count' => (int) $r['count'] ];
			}, $top_urls ?: [] ),
			'ua_distribution'      => array_map( function( $r ) {
				return [ 'user_agent' => mb_substr( (string) $r['user_agent'], 0, 300 ), 'count' => (int) $r['count'] ];
			}, $ua_distribution ?: [] ),
			'fingerprint_signals'  => $fp_signals,
		];
	}

	/**
	 * Aggregate browser fingerprint anomaly rates for attack window.
	 */
	private function build_fingerprint_signals( string $cutoff ): array {
		$histogram = $this->stats->get_top_factor_histogram( 1, 0 ); // last 1h, all scores
		$top       = array_slice( $histogram['items'] ?? [], 0, 10 );

		// Also compute specific signal rates from top_factor column.
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'baskerville_stats' );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$total = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$table}
			 WHERE timestamp_utc >= %s AND had_fp = 1",
			$cutoff
		) );

		$signals = [];
		$keys    = [ 'webdriver', 'mobile_ua_no_touch', 'http1_protocol', 'language_mismatch', 'no_web_gl' ];
		$map     = [
			'webdriver'          => 'webdriver_pct',
			'mobile_ua_no_touch' => 'no_touch_mobile_pct',
			'http1_protocol'     => 'http1_pct',
			'language_mismatch'  => 'lang_mismatch_pct',
			'no_web_gl'          => 'no_webgl_pct',
		];

		if ( $total > 0 ) {
			foreach ( $keys as $key ) {
				$cnt = (int) $wpdb->get_var( $wpdb->prepare(
					"SELECT COUNT(*) FROM {$table}
					 WHERE timestamp_utc >= %s AND had_fp = 1 AND top_factor = %s",
					$cutoff, $key
				) );
				$signals[ $map[ $key ] ] = round( $cnt * 100 / $total, 1 );
			}
		} else {
			foreach ( $map as $pct_key ) {
				$signals[ $pct_key ] = 0.0;
			}
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$signals['top_factors'] = $top;
		return $signals;
	}

	// -------------------------------------------------------------------------
	// API calls
	// -------------------------------------------------------------------------

	/**
	 * Fire-and-forget POST. Returns job_id or null on failure.
	 */
	private function submit_analysis( array $payload ): ?string {
		$response = wp_remote_post(
			self::API_BASE . '/analyze',
			[
				'timeout'  => 15,
				'blocking' => true, // need the job_id back, but LLM runs async server-side
				'headers'  => [ 'Content-Type' => 'application/json' ],
				'body'     => wp_json_encode( $payload ),
			]
		);

		if ( is_wp_error( $response ) ) {
			wpsec_log( 'Baskerville Cloud: submit failed — ' . $response->get_error_message() );
			return null;
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			wpsec_log( "Baskerville Cloud: submit HTTP {$code}" );
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return $body['job_id'] ?? null;
	}

	// -------------------------------------------------------------------------
	// Polling
	// -------------------------------------------------------------------------

	private function poll_pending_job(): void {
		$pending = get_option( self::OPTION_PENDING );
		if ( ! $pending || empty( $pending['job_id'] ) ) {
			return;
		}

		// Expire after 2 hours.
		if ( time() - (int) $pending['submitted_at'] > 7200 ) {
			wpsec_log( 'Baskerville Cloud: job ' . $pending['job_id'] . ' expired, discarding.' );
			delete_option( self::OPTION_PENDING );
			return;
		}

		$response = wp_remote_get(
			self::API_BASE . '/report/' . $pending['job_id'],
			[ 'timeout' => 10 ]
		);

		if ( is_wp_error( $response ) ) {
			wpsec_log( 'Baskerville Cloud: poll failed — ' . $response->get_error_message() );
			return;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		$status = $body['status'] ?? 'pending';

		if ( $status === 'pending' ) {
			return; // still processing
		}

		delete_option( self::OPTION_PENDING );

		if ( $status === 'error' ) {
			wpsec_log( 'Baskerville Cloud: job failed — ' . ( $body['error'] ?? 'unknown' ) );
			return;
		}

		if ( $status === 'ready' ) {
			$this->save_report( $body );
			$this->apply_action( $body['action'] ?? 'none', $body['target'] ?? null );
		}
	}

	// -------------------------------------------------------------------------
	// Persistence & action
	// -------------------------------------------------------------------------

	private function save_report( array $body ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_reports';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->insert( $table, [
			'domain'          => parse_url( get_site_url(), PHP_URL_HOST ),
			'created_at'      => current_time( 'mysql', true ),
			'action'          => sanitize_text_field( $body['action'] ?? 'none' ),
			'target'          => sanitize_text_field( $body['target'] ?? '' ),
			'reasoning'       => sanitize_textarea_field( $body['reasoning'] ?? '' ),
			'report_markdown' => wp_kses_post( $body['report_markdown'] ?? '' ),
			'applied'         => 0,
		], [ '%s', '%s', '%s', '%s', '%s', '%s', '%d' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		wpsec_log( 'Baskerville Cloud: report saved, action=' . ( $body['action'] ?? 'none' ) );
	}

	private function apply_action( string $action, ?string $target ): void {
		// TODO: wire up to firewall rules when block_asn / block_country implemented.
		// For now: log the recommendation, admin reviews in dashboard.
		wpsec_log( "Baskerville Cloud: recommended action={$action}, target={$target}" );
	}

	// -------------------------------------------------------------------------
	// DB schema
	// -------------------------------------------------------------------------

	public function create_reports_table(): void {
		global $wpdb;
		$table          = $wpdb->prefix . 'baskerville_reports';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id bigint(20) NOT NULL AUTO_INCREMENT,
			domain varchar(255) NOT NULL,
			created_at datetime NOT NULL,
			action varchar(32) NOT NULL DEFAULT 'none',
			target varchar(128) NULL,
			reasoning text NULL,
			report_markdown longtext NULL,
			applied tinyint(1) NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			KEY created_at (created_at),
			KEY action (action)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	// -------------------------------------------------------------------------
	// Helpers
	// -------------------------------------------------------------------------

	public function is_enabled(): bool {
		$key = get_option( self::OPTION_LICENSE, '' );
		return ! empty( $key );
	}
}
