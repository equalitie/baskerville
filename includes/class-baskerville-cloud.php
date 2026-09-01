<?php
/**
 * Baskerville Cloud — LLM-powered incident analysis (Level 1: cluster/traffic analysis).
 *
 * Flow:
 *   Every 5 min (WP Cron):
 *     1. save_snapshot()  — always, regardless of license.
 *     2. poll_pending_job() — fetch LLM result for any pending job.
 *     3. monitor_incident() — close active incident if traffic normalized.
 *     4. detect_spike() via snapshots → start_incident() → submit_analysis().
 *
 * Spike detection uses wp_baskerville_snapshots (not raw stats), so detection
 * and payload building are consistent and cheap.
 */

if ( ! defined( 'ABSPATH' ) ) exit;

class Baskerville_Cloud {

	const API_BASE          = 'https://api.baskerville.ai/v1';
	const OPTION_LICENSE    = 'baskerville_cloud_license_key';
	const OPTION_API_SECRET = 'baskerville_cloud_api_secret';       // shared secret for X-Baskerville-Key
	const OPTION_PENDING    = 'baskerville_cloud_pending_job';      // {job_id, submitted_at, incident_id}
	const OPTION_LAST_SPIKE = 'baskerville_cloud_last_spike';       // unix timestamp
	const OPTION_ACTIVE_INC      = 'baskerville_cloud_active_incident';   // incident_id (int)
	const OPTION_WATCHDOG_JOB    = 'baskerville_watchdog_pending';         // {job_id, submitted_at}
	const OPTION_WATCHDOG_TEXT   = 'baskerville_watchdog_summary';         // plain text (Status\nSentences)
	const OPTION_WATCHDOG_TIME   = 'baskerville_watchdog_generated_at';    // unix timestamp
	const OPTION_WATCHDOG_DATE   = 'baskerville_watchdog_last_day';        // Y-m-d of yesterday the last watchdog covered

	// Spike thresholds
	const TRAFFIC_SPIKE_FACTOR   = 3.0;  // current snapshot vs baseline average
	const DECISIONS_SPIKE_FACTOR = 3.0;  // blocks+challenges spike factor
	const SPIKE_COOLDOWN_SEC     = 1800; // 30 min between incidents
	const SNAPSHOT_WINDOW_SEC    = 300;  // 5 min per snapshot
	const BASELINE_SNAPSHOTS     = 6;    // 6 × 5 min = 30 min baseline
	const SNAPSHOT_RETENTION_H   = 168;  // hours to keep snapshots (7 days)

	/** @var Baskerville_Stats */
	private $stats;

	public function __construct( Baskerville_Stats $stats ) {
		$this->stats = $stats;
		$this->maybe_create_tables();
	}

	/**
	 * Ensure DB tables exist. Runs once per plugin version via option flag.
	 * Safe to call on every load — dbDelta is idempotent, but we gate it with
	 * a version option to avoid the overhead on every request.
	 */
	private function maybe_create_tables(): void {
		$installed = get_option( 'baskerville_cloud_db_version', '' );
		if ( $installed === BASKERVILLE_VERSION ) {
			return;
		}
		$this->create_snapshots_table();
		$this->create_daily_table();
		update_option( 'baskerville_cloud_db_version', BASKERVILLE_VERSION );
	}

	// =========================================================================
	// Main entry point (WP Cron every 5 min)
	// =========================================================================

	public function maybe_analyze(): void {
		// 1. Snapshot always — even if no license.
		$this->save_snapshot();

		// 2. Poll pending watchdog job — requires only API secret, not license.
		if ( $this->has_api_access() ) {
			$this->poll_watchdog_job();

			// Ensure one watchdog per day: if yesterday's report hasn't been generated
			// yet and no job is pending, submit now. Handles the case where daily
			// rollup exits early (idempotent check) without calling submit_watchdog().
			$pending_job   = get_option( self::OPTION_WATCHDOG_JOB );
			$yesterday     = gmdate( 'Y-m-d', strtotime( '-1 day' ) );
			$last_day      = get_option( self::OPTION_WATCHDOG_DATE, '' );
			wpsec_log( sprintf(
				'Baskerville Cloud: watchdog check — pending=%s last_day=%s yesterday=%s',
				$pending_job ? ( $pending_job['job_id'] ?? 'set' ) : 'none',
				$last_day ?: 'none',
				$yesterday
			) );
			if ( empty( $pending_job ) && $last_day !== $yesterday ) {
				wpsec_log( 'Baskerville Cloud: watchdog daily trigger for ' . $yesterday );
				// Ensure daily rollup exists before submitting watchdog.
				// run_daily_rollup() is idempotent — safe to call every 5 min.
				// It also calls submit_watchdog() internally when it creates the daily row.
				$this->run_daily_rollup();
				// Only submit if run_daily_rollup() didn't already do it
				// (i.e., it exited early because the daily row already existed).
				$after_job = get_option( self::OPTION_WATCHDOG_JOB );
				if ( empty( $after_job ) ) {
					$this->submit_watchdog( $yesterday );
				}
			}
		}

		if ( ! $this->is_enabled() ) {
			return;
		}

		// 3. Poll any pending LLM incident analysis job.
		$this->poll_pending_job();

		// 3b. Monitor active incident — close if traffic normalized.
		$this->monitor_incident();

		// 4. Cooldown / de-dup guards.
		$last_spike = (int) get_option( self::OPTION_LAST_SPIKE, 0 );
		if ( time() - $last_spike < self::SPIKE_COOLDOWN_SEC ) {
			return;
		}
		if ( get_option( self::OPTION_PENDING ) ) {
			return;
		}
		if ( get_option( self::OPTION_ACTIVE_INC ) ) {
			return;
		}

		// 5. Detect spike from snapshots.
		$spike = $this->detect_spike();
		if ( ! $spike ) {
			return;
		}

		wpsec_log( "Baskerville Cloud: spike detected ({$spike['type']}, {$spike['factor']}x). Submitting analysis." );

		// 6. Create incident record.
		$incident_id = $this->start_incident( $spike );

		// 7. Build payload and submit.
		$payload = $this->build_payload( $spike );
		$job_id  = $this->submit_analysis( $payload );

		if ( $job_id ) {
			update_option( self::OPTION_PENDING, [
				'job_id'       => $job_id,
				'submitted_at' => time(),
				'incident_id'  => $incident_id,
			] );
			update_option( self::OPTION_LAST_SPIKE, time() );
			update_option( self::OPTION_ACTIVE_INC, $incident_id );
			wpsec_log( "Baskerville Cloud: job={$job_id}, incident={$incident_id}" );
		} elseif ( $incident_id ) {
			$this->close_incident( $incident_id, 'submit_failed' );
		}
	}

	// =========================================================================
	// Snapshot
	// =========================================================================

	/**
	 * Save a snapshot for the last complete 5-min window.
	 * Idempotent: skips if already saved for this window.
	 * Called unconditionally every cron run — no license required.
	 */
	public function save_snapshot(): void {
		global $wpdb;
		$table      = esc_sql( $wpdb->prefix . 'baskerville_stats' );
		$snap_table = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );

		$window_end   = (int) ( floor( time() / self::SNAPSHOT_WINDOW_SEC ) * self::SNAPSHOT_WINDOW_SEC );
		$window_start = $window_end - self::SNAPSHOT_WINDOW_SEC;
		$snap_at      = gmdate( 'Y-m-d H:i:s', $window_end );
		$ts_start     = gmdate( 'Y-m-d H:i:s', $window_start );
		$ts_end       = gmdate( 'Y-m-d H:i:s', $window_end );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$exists = $wpdb->get_var( $wpdb->prepare(
			"SELECT 1 FROM {$snap_table} WHERE snapshot_at = %s LIMIT 1",
			$snap_at
		) );
		if ( $exists ) {
			return;
		}

		// Core counts.
		$counts = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				COUNT(*)  AS traffic_count,
				SUM(CASE WHEN event_type = 'block' THEN 1 ELSE 0 END) AS block_count,
				SUM(CASE WHEN classification IN ('bot','bad_bot') AND event_type != 'block' THEN 1 ELSE 0 END) AS challenge_count,
				COUNT(DISTINCT ip) AS unique_ips,
				ROUND(100 * SUM(CASE WHEN (baskerville_id IS NULL OR baskerville_id = '') THEN 1 ELSE 0 END) / COUNT(*), 1) AS no_cookie_pct
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND event_type IN ('page','fp','block')",
			$ts_start, $ts_end
		), ARRAY_A );

		$traffic = (int) ( $counts['traffic_count'] ?? 0 );

		// Unique sessions + immature ratio (1-request sessions).
		$session_stats = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				COUNT(DISTINCT session_key) AS total_sessions,
				SUM(CASE WHEN cnt = 1 THEN 1 ELSE 0 END) AS immature_sessions
			 FROM (
				SELECT COALESCE(NULLIF(baskerville_id,''), ip) AS session_key, COUNT(*) AS cnt
				FROM {$table}
				WHERE timestamp_utc >= %s AND timestamp_utc < %s
				  AND event_type IN ('page','fp','block')
				GROUP BY session_key
			 ) sub",
			$ts_start, $ts_end
		), ARRAY_A );

		$unique_sessions = (int) ( $session_stats['total_sessions'] ?? 0 );
		$immature        = (int) ( $session_stats['immature_sessions'] ?? 0 );
		$immature_ratio  = $unique_sessions > 0 ? round( $immature / $unique_sessions, 4 ) : 0.0;

		// Country histogram.
		$countries = $wpdb->get_results( $wpdb->prepare(
			"SELECT COALESCE(NULLIF(country_code,''),'XX') AS k, COUNT(*) AS v
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND event_type IN ('page','fp','block')
			 GROUP BY k ORDER BY v DESC LIMIT 20",
			$ts_start, $ts_end
		), ARRAY_A );

		// Fingerprint histogram (top_factor).
		$fingerprints = $wpdb->get_results( $wpdb->prepare(
			"SELECT top_factor AS k, COUNT(*) AS v
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND had_fp = 1 AND top_factor IS NOT NULL AND top_factor != ''
			 GROUP BY k ORDER BY v DESC LIMIT 20",
			$ts_start, $ts_end
		), ARRAY_A );

		// UA histogram — top 100 for bot detection, store top 20 in ua_json.
		$ua_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT user_agent AS k, COUNT(*) AS v
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND event_type IN ('page','fp','block')
			   AND user_agent IS NOT NULL AND user_agent != ''
			 GROUP BY k ORDER BY v DESC LIMIT 100",
			$ts_start, $ts_end
		), ARRAY_A );

		// ASN histogram.
		$asns = $wpdb->get_results( $wpdb->prepare(
			"SELECT asn AS k, COUNT(*) AS v
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND event_type IN ('page','fp','block')
			   AND asn IS NOT NULL AND asn != ''
			 GROUP BY k ORDER BY v DESC LIMIT 20",
			$ts_start, $ts_end
		), ARRAY_A );

		// Classification breakdown: human / bot / bad_bot / borderline.
		$classifications = $wpdb->get_results( $wpdb->prepare(
			"SELECT COALESCE(NULLIF(classification,''),'unknown') AS k, COUNT(*) AS v
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND timestamp_utc < %s
			   AND event_type IN ('page','fp','block')
			 GROUP BY k",
			$ts_start, $ts_end
		), ARRAY_A );

		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		// Known bot detection via UA matching (PHP-side, no extra SQL).
		$bot_data   = Baskerville_AI_Bots::aggregate( $ua_rows );
		$known_bots = $bot_data['known_bots'];
		$ai_traffic = $bot_data['ai_traffic'];

		$to_json = function( array $rows ): string {
			$out = [];
			foreach ( $rows as $r ) {
				$out[ (string) $r['k'] ] = (int) $r['v'];
			}
			return wp_json_encode( $out ) ?: '{}';
		};

		// Top 20 UAs for ua_json.
		$uas = array_slice( $ua_rows, 0, 20 );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->insert( $snap_table, [
			'snapshot_at'          => $snap_at,
			'traffic_count'        => $traffic,
			'block_count'          => (int) ( $counts['block_count'] ?? 0 ),
			'challenge_count'      => (int) ( $counts['challenge_count'] ?? 0 ),
			'unique_ips'           => (int) ( $counts['unique_ips'] ?? 0 ),
			'unique_sessions'      => $unique_sessions,
			'immature_ratio'       => $immature_ratio,
			'no_cookie_pct'        => (float) ( $counts['no_cookie_pct'] ?? 0.0 ),
			'countries_json'       => $to_json( $countries ),
			'fingerprints_json'    => $to_json( $fingerprints ),
			'ua_json'              => $to_json( $uas ),
			'asn_json'             => $to_json( $asns ),
			'classifications_json' => $to_json( $classifications ),
			'known_bots_json'      => wp_json_encode( $known_bots ) ?: '{}',
			'ai_traffic_json'      => wp_json_encode( $ai_traffic ) ?: '{}',
		], [ '%s', '%d', '%d', '%d', '%d', '%d', '%f', '%f', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery
	}

	// =========================================================================
	// Spike detection (via snapshots)
	// =========================================================================

	/**
	 * Returns ['type' => 'traffic|decisions|both', 'factor' => float] or null.
	 * Reads last BASELINE_SNAPSHOTS+1 rows; current = most recent, rest = baseline.
	 */
	private function detect_spike(): ?array {
		global $wpdb;
		$snap_table = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$limit      = self::BASELINE_SNAPSHOTS + 1;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$snaps = $wpdb->get_results(
			"SELECT traffic_count, block_count, challenge_count
			 FROM {$snap_table}
			 ORDER BY snapshot_at DESC
			 LIMIT {$limit}",
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		if ( count( $snaps ) < 3 ) {
			return null; // not enough history yet
		}

		$current  = array_shift( $snaps ); // most recent
		$baseline = $snaps;
		$n        = count( $baseline );

		$avg_traffic = array_sum( array_column( $baseline, 'traffic_count' ) ) / $n;

		$baseline_dec = array_map(
			function( $r ) { return (int) $r['block_count'] + (int) $r['challenge_count']; },
			$baseline
		);
		$avg_decisions = array_sum( $baseline_dec ) / $n;

		$current_decisions = (int) $current['block_count'] + (int) $current['challenge_count'];

		$traffic_factor   = $avg_traffic   > 0 ? (float) $current['traffic_count'] / $avg_traffic   : 0.0;
		$decisions_factor = $avg_decisions > 0 ? (float) $current_decisions        / $avg_decisions : 0.0;

		$t_spike = $traffic_factor   >= self::TRAFFIC_SPIKE_FACTOR;
		$d_spike = $decisions_factor >= self::DECISIONS_SPIKE_FACTOR;

		if ( ! $t_spike && ! $d_spike ) {
			return null;
		}

		$type   = ( $t_spike && $d_spike ) ? 'both' : ( $t_spike ? 'traffic' : 'decisions' );
		$factor = round( max( $traffic_factor, $decisions_factor ), 1 );

		return [ 'type' => $type, 'factor' => $factor ];
	}

	// =========================================================================
	// Payload builder
	// =========================================================================

	private function build_payload( array $spike ): array {
		global $wpdb;
		$table      = esc_sql( $wpdb->prefix . 'baskerville_stats' );
		$snap_table = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$limit      = self::BASELINE_SNAPSHOTS + 1;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery

		// Load last N+1 snapshots (newest first).
		$snaps = $wpdb->get_results(
			"SELECT * FROM {$snap_table} ORDER BY snapshot_at DESC LIMIT {$limit}",
			ARRAY_A
		);

		$current_snap  = ! empty( $snaps ) ? array_shift( $snaps ) : [];
		$baseline_snaps = $snaps;

		$current_snapshot  = $this->decode_snapshot( $current_snap );
		$baseline_snapshot = $this->average_snapshots( $baseline_snaps );

		// Timeline: 5-min buckets for last 30 min.
		$cutoff   = gmdate( 'Y-m-d H:i:s', time() - 1800 );
		$timeline = $wpdb->get_results( $wpdb->prepare(
			"SELECT
				DATE_FORMAT(FROM_UNIXTIME(FLOOR(UNIX_TIMESTAMP(timestamp_utc)/300)*300), '%%Y-%%m-%%d %%H:%%i') AS bucket,
				COUNT(*) AS requests,
				SUM(CASE WHEN event_type = 'block' THEN 1 ELSE 0 END) AS blocks,
				SUM(CASE WHEN classification IN ('bot','bad_bot') AND event_type != 'block' THEN 1 ELSE 0 END) AS challenges
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY bucket ORDER BY bucket ASC",
			$cutoff
		), ARRAY_A );

		// Top URLs in attack window.
		$top_urls = $wpdb->get_results( $wpdb->prepare(
			"SELECT page_url AS url, COUNT(*) AS count
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY page_url ORDER BY count DESC LIMIT 10",
			$cutoff
		), ARRAY_A );

		// IP overlap: attacking IPs also seen as bots in last 90 days.
		$attack_start  = $cutoff;
		$lookback_days = gmdate( 'Y-m-d H:i:s', time() - 90 * 86400 );

		$overlap = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				COUNT(DISTINCT s.ip) AS overlap_count,
				(SELECT COUNT(DISTINCT ip) FROM {$table}
				 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')) AS attack_ips,
				MAX(prev.timestamp_utc) AS last_seen
			 FROM {$table} s
			 INNER JOIN (
				SELECT DISTINCT ip FROM {$table}
				WHERE timestamp_utc < %s
				  AND timestamp_utc >= %s
				  AND classification IN ('bad_bot','bot')
			 ) prev ON prev.ip = s.ip
			 WHERE s.timestamp_utc >= %s
			   AND s.event_type IN ('page','fp','block')",
			$attack_start,  // attack_ips subquery
			$attack_start,  // prev window end
			$lookback_days, // prev window start
			$attack_start   // main WHERE
		), ARRAY_A );

		$attack_ips    = (int) ( $overlap['attack_ips'] ?? 0 );
		$overlap_count = (int) ( $overlap['overlap_count'] ?? 0 );
		$overlap_pct   = $attack_ips > 0 ? round( $overlap_count * 100 / $attack_ips, 1 ) : 0.0;

		$ip_overlap = [
			'overlap_count' => $overlap_count,
			'overlap_pct'   => $overlap_pct,
			'last_seen'     => $overlap['last_seen'] ? substr( $overlap['last_seen'], 0, 10 ) : null,
		];

		// Auto-block concentrated attack (top N IPs > 80% of traffic).
		$auto_blocked = $this->check_auto_block( $cutoff );

		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return [
			'license_key'       => (string) get_option( self::OPTION_LICENSE, '' ),
			'domain'            => parse_url( get_site_url(), PHP_URL_HOST ),
			'spike_type'        => $spike['type'],
			'spike_factor'      => $spike['factor'],
			'unique_ips'        => $current_snapshot['unique_ips'] ?? 0,
			'no_cookie_pct'     => $current_snapshot['no_cookie_pct'] ?? 0.0,
			'timeline'          => array_map( function( $r ) {
				return [
					'bucket'     => $r['bucket'],
					'requests'   => (int) $r['requests'],
					'blocks'     => (int) $r['blocks'],
					'challenges' => (int) $r['challenges'],
				];
			}, $timeline ?: [] ),
			'current_snapshot'  => $current_snapshot,
			'baseline_snapshot' => $baseline_snapshot,
			'top_urls'          => array_map( function( $r ) {
				return [ 'url' => mb_substr( (string) $r['url'], 0, 200 ), 'count' => (int) $r['count'] ];
			}, $top_urls ?: [] ),
			'auto_blocked_ips'  => $auto_blocked,
			'ip_overlap'        => $ip_overlap,
		];
	}

	/**
	 * Decode a snapshot row from DB into payload-ready array.
	 */
	private function decode_snapshot( array $snap ): array {
		if ( empty( $snap ) ) {
			return [];
		}
		return [
			'traffic_count'   => (int) $snap['traffic_count'],
			'block_count'     => (int) $snap['block_count'],
			'challenge_count' => (int) $snap['challenge_count'],
			'unique_ips'      => (int) $snap['unique_ips'],
			'unique_sessions' => (int) $snap['unique_sessions'],
			'immature_ratio'  => (float) $snap['immature_ratio'],
			'no_cookie_pct'   => (float) $snap['no_cookie_pct'],
			'countries'        => json_decode( $snap['countries_json'] ?? '{}', true ) ?: (object) [],
			'fingerprints'     => json_decode( $snap['fingerprints_json'] ?? '{}', true ) ?: (object) [],
			'user_agents'      => json_decode( $snap['ua_json'] ?? '{}', true ) ?: (object) [],
			'asns'             => json_decode( $snap['asn_json'] ?? '{}', true ) ?: (object) [],
			'classifications'  => json_decode( $snap['classifications_json'] ?? '{}', true ) ?: (object) [],
			'known_bots'       => json_decode( $snap['known_bots_json'] ?? '{}', true ) ?: (object) [],
		];
	}

	/**
	 * Average N snapshot rows into a single baseline snapshot.
	 * Numeric fields are averaged; histograms are summed then divided by N.
	 */
	private function average_snapshots( array $snaps ): array {
		$n = count( $snaps );
		if ( $n === 0 ) {
			return [];
		}

		$numeric = [
			'traffic_count'   => 0,
			'block_count'     => 0,
			'challenge_count' => 0,
			'unique_ips'      => 0,
			'unique_sessions' => 0,
			'immature_ratio'  => 0.0,
			'no_cookie_pct'   => 0.0,
		];

		$histo_cols = [
			'countries_json'       => 'countries',
			'fingerprints_json'    => 'fingerprints',
			'ua_json'              => 'user_agents',
			'asn_json'             => 'asns',
			'classifications_json' => 'classifications',
		];
		// known_bots is nested (category → company → count), averaged separately below.
		$histo_sums = array_fill_keys( array_values( $histo_cols ), [] );

		foreach ( $snaps as $snap ) {
			foreach ( array_keys( $numeric ) as $key ) {
				$numeric[ $key ] += (float) ( $snap[ $key ] ?? 0 );
			}
			foreach ( $histo_cols as $col => $field ) {
				$data = json_decode( $snap[ $col ] ?? '{}', true ) ?: [];
				foreach ( $data as $k => $v ) {
					$histo_sums[ $field ][ $k ] = ( $histo_sums[ $field ][ $k ] ?? 0 ) + (int) $v;
				}
			}
		}

		$result = [];
		foreach ( $numeric as $key => $sum ) {
			$result[ $key ] = in_array( $key, [ 'immature_ratio', 'no_cookie_pct' ], true )
				? round( $sum / $n, 4 )
				: (int) round( $sum / $n );
		}

		foreach ( $histo_cols as $field ) {
			$avg = $histo_sums[ $field ];
			foreach ( $avg as $k => &$v ) {
				$v = (int) round( $v / $n );
			}
			unset( $v );
			arsort( $avg );
			$result[ $field ] = $avg ?: (object) [];
		}

		// Average known_bots (nested: category → company → count).
		$known_bots_sum = [];
		foreach ( $snaps as $snap ) {
			$data = json_decode( $snap['known_bots_json'] ?? '{}', true ) ?: [];
			foreach ( $data as $cat => $companies ) {
				foreach ( $companies as $company => $cnt ) {
					$known_bots_sum[ $cat ][ $company ] = ( $known_bots_sum[ $cat ][ $company ] ?? 0 ) + (int) $cnt;
				}
			}
		}
		foreach ( $known_bots_sum as $cat => &$companies ) {
			foreach ( $companies as &$v ) {
				$v = (int) round( $v / $n );
			}
			unset( $v );
			arsort( $companies );
		}
		unset( $companies );
		$result['known_bots'] = $known_bots_sum ?: (object) [];

		return $result;
	}

	/**
	 * Check for concentrated attack: top N IPs > 80% of traffic.
	 * Returns metadata only (LLM is informed, not the decision-maker here).
	 */
	private function check_auto_block( string $cutoff ): array {
		global $wpdb;
		$table = esc_sql( $wpdb->prefix . 'baskerville_stats' );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$total = (int) $wpdb->get_var( $wpdb->prepare(
			"SELECT COUNT(*) FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')",
			$cutoff
		) );

		if ( $total === 0 ) {
			return [ 'count' => 0, 'pct_of_attack_traffic' => 0.0, 'action' => 'none' ];
		}

		$top_ips = $wpdb->get_results( $wpdb->prepare(
			"SELECT ip, COUNT(*) AS cnt
			 FROM {$table}
			 WHERE timestamp_utc >= %s AND event_type IN ('page','fp','block')
			 GROUP BY ip
			 ORDER BY cnt DESC
			 LIMIT 50",
			$cutoff
		), ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$cumulative = 0;
		$concentrated_n = 0;
		foreach ( $top_ips as $row ) {
			$cumulative += (int) $row['cnt'];
			$concentrated_n++;
			if ( $cumulative / $total >= 0.80 ) {
				break;
			}
		}

		$pct    = round( $cumulative * 100 / $total, 1 );
		$action = ( $pct >= 80.0 && $concentrated_n <= 50 ) ? 'blocked' : 'none';

		// TODO: when action='blocked', apply IP blocks to firewall cache.

		return [
			'count'                => $concentrated_n,
			'pct_of_attack_traffic' => $pct,
			'action'               => $action,
		];
	}

	// =========================================================================
	// Incident lifecycle
	// =========================================================================

	private function start_incident( array $spike ): int {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_incidents';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->insert( $table, [
			'started_at'   => current_time( 'mysql', true ),
			'status'       => 'active',
			'spike_type'   => $spike['type'],
			'spike_factor' => $spike['factor'],
		], [ '%s', '%s', '%s', '%f' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		return (int) $wpdb->insert_id;
	}

	/**
	 * Check if active incident should be closed (traffic back to baseline).
	 */
	private function monitor_incident(): void {
		$incident_id = (int) get_option( self::OPTION_ACTIVE_INC, 0 );
		if ( ! $incident_id ) {
			return;
		}

		// Simple check: current snapshot traffic < 1.5x baseline average.
		global $wpdb;
		$snap_table = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$limit      = self::BASELINE_SNAPSHOTS + 1;

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$snaps = $wpdb->get_results(
			"SELECT traffic_count FROM {$snap_table}
			 ORDER BY snapshot_at DESC LIMIT {$limit}",
			ARRAY_A
		);
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		if ( count( $snaps ) < 3 ) {
			return;
		}

		$current  = (int) array_shift( $snaps )['traffic_count'];
		$baseline = $snaps;
		$avg      = array_sum( array_column( $baseline, 'traffic_count' ) ) / count( $baseline );

		if ( $avg > 0 && $current / $avg < 1.5 ) {
			$this->close_incident( $incident_id, 'normalized' );
			delete_option( self::OPTION_ACTIVE_INC );
			wpsec_log( "Baskerville Cloud: incident {$incident_id} closed — traffic normalized." );
		}
	}

	private function close_incident( int $incident_id, string $reason ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_incidents';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->update( $table, [
			'ended_at' => current_time( 'mysql', true ),
			'status'   => 'closed',
			'reasoning' => $reason,
		], [ 'id' => $incident_id ], [ '%s', '%s', '%s' ], [ '%d' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery
	}

	private function finish_incident( int $incident_id, array $body ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_incidents';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->update( $table, [
			'actions_json'    => wp_json_encode( $body['actions'] ?? [] ),
			'reasoning'       => sanitize_textarea_field( $body['reasoning'] ?? '' ),
			'report_markdown' => wp_kses_post( $body['report_markdown'] ?? '' ),
		], [ 'id' => $incident_id ], [ '%s', '%s', '%s' ], [ '%d' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery
	}

	// =========================================================================
	// API calls
	// =========================================================================

	private function api_headers(): array {
		return [
			'Content-Type'      => 'application/json',
			'X-Baskerville-Key' => (string) get_option( self::OPTION_API_SECRET, '' ),
		];
	}

	private function submit_analysis( array $payload ): ?string {
		$response = wp_remote_post(
			self::API_BASE . '/analyze',
			[
				'timeout'  => 15,
				'blocking' => true,
				'headers'  => $this->api_headers(),
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

	// =========================================================================
	// Polling
	// =========================================================================

	private function poll_pending_job(): void {
		$pending = get_option( self::OPTION_PENDING );
		if ( ! $pending || empty( $pending['job_id'] ) ) {
			return;
		}

		if ( time() - (int) $pending['submitted_at'] > 7200 ) {
			wpsec_log( 'Baskerville Cloud: job ' . $pending['job_id'] . ' expired.' );
			delete_option( self::OPTION_PENDING );
			delete_option( self::OPTION_ACTIVE_INC );
			return;
		}

		$response = wp_remote_get(
			self::API_BASE . '/report/' . $pending['job_id'],
			[ 'timeout' => 10, 'headers' => $this->api_headers() ]
		);

		if ( is_wp_error( $response ) ) {
			wpsec_log( 'Baskerville Cloud: poll failed — ' . $response->get_error_message() );
			return;
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		if ( $http_code === 404 ) {
			wpsec_log( 'Baskerville Cloud: job ' . $pending['job_id'] . ' not found (pod restart?), clearing.' );
			delete_option( self::OPTION_PENDING );
			delete_option( self::OPTION_ACTIVE_INC );
			return;
		}
		if ( $http_code !== 200 ) {
			return;
		}

		$body   = json_decode( wp_remote_retrieve_body( $response ), true );
		$status = $body['status'] ?? 'pending';

		if ( $status === 'pending' ) {
			return;
		}

		$incident_id = (int) ( $pending['incident_id'] ?? 0 );
		delete_option( self::OPTION_PENDING );

		if ( $status === 'error' ) {
			wpsec_log( 'Baskerville Cloud: job failed — ' . ( $body['error'] ?? 'unknown' ) );
			return;
		}

		if ( $status === 'ready' ) {
			$this->save_report( $body, $incident_id );
			if ( $incident_id ) {
				$this->finish_incident( $incident_id, $body );
			}
			$this->apply_actions( $body['actions'] ?? [] );
		}
	}

	// =========================================================================
	// Actions
	// =========================================================================

	/**
	 * Apply LLM-recommended actions to the firewall.
	 * Stores temporary blocks in a transient checked by pre_db_firewall() on every request.
	 *
	 * Action format from LLM: { type: block_country|block_asn|block_useragent, target: string, ttl_hours: int }
	 */
	private function apply_actions( array $actions ): void {
		if ( empty( $actions ) ) {
			return;
		}

		// Load existing cloud blocks, prune expired ones.
		$blocks = get_transient( 'baskerville_cloud_blocks' ) ?: [];
		$now    = time();
		$blocks = array_filter( $blocks, fn( $b ) => $b['expires'] > $now );

		foreach ( $actions as $action ) {
			$type   = sanitize_key( $action['type'] ?? 'none' );
			$target = sanitize_text_field( $action['target'] ?? '' );
			$ttl    = (int) ( $action['ttl_hours'] ?? 2 );

			if ( ! $type || ! $target ) {
				continue;
			}

			wpsec_log( "Baskerville Cloud: action={$type}, target={$target}, ttl={$ttl}h" );

			switch ( $type ) {
				case 'block_country':
				case 'block_asn':
				case 'block_useragent':
					$blocks[] = [
						'type'    => $type,
						'target'  => strtoupper( $target ),
						'expires' => $now + $ttl * 3600,
					];
					break;

				case 'raise_threshold':
					// Temporarily lower the challenge threshold (raise sensitivity).
					$current = (int) get_option( 'baskerville_settings', [] )['challenge_min'] ?? 40;
					set_transient( 'baskerville_cloud_threshold', max( 10, $current - 20 ), $ttl * 3600 );
					wpsec_log( "Baskerville Cloud: challenge threshold temporarily lowered for {$ttl}h" );
					break;
			}
		}

		// Store blocks — TTL of the transient itself is the longest individual block.
		if ( ! empty( $blocks ) ) {
			$max_ttl = max( array_map( fn( $b ) => $b['expires'] - $now, $blocks ) );
			set_transient( 'baskerville_cloud_blocks', array_values( $blocks ), $max_ttl );
			wpsec_log( 'Baskerville Cloud: ' . count( $blocks ) . ' active cloud blocks stored.' );
		}
	}

	// =========================================================================
	// Persistence
	// =========================================================================

	private function save_report( array $body, int $incident_id = 0 ): void {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_reports';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->insert( $table, [
			'incident_id'     => $incident_id ?: null,
			'domain'          => parse_url( get_site_url(), PHP_URL_HOST ),
			'created_at'      => current_time( 'mysql', true ),
			'actions_json'    => wp_json_encode( $body['actions'] ?? [] ),
			'reasoning'       => sanitize_textarea_field( $body['reasoning'] ?? '' ),
			'report_markdown' => wp_kses_post( $body['report_markdown'] ?? '' ),
			'applied'         => 0,
		], [ '%d', '%s', '%s', '%s', '%s', '%s', '%d' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		wpsec_log( 'Baskerville Cloud: report saved, actions=' . count( $body['actions'] ?? [] ) );
	}

	// =========================================================================
	// DB schema
	// =========================================================================

	public function create_snapshots_table(): void {
		global $wpdb;
		$table           = $wpdb->prefix . 'baskerville_snapshots';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			snapshot_at          datetime  NOT NULL,
			traffic_count        int       NOT NULL DEFAULT 0,
			block_count          int       NOT NULL DEFAULT 0,
			challenge_count      int       NOT NULL DEFAULT 0,
			unique_ips           int       NOT NULL DEFAULT 0,
			unique_sessions      int       NOT NULL DEFAULT 0,
			immature_ratio       float     NOT NULL DEFAULT 0,
			no_cookie_pct        float     NOT NULL DEFAULT 0,
			countries_json       longtext  NULL,
			fingerprints_json    longtext  NULL,
			ua_json              longtext  NULL,
			asn_json             longtext  NULL,
			classifications_json longtext  NULL,
			known_bots_json      longtext  NULL,
			ai_traffic_json      longtext  NULL,
			PRIMARY KEY (snapshot_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public function create_daily_table(): void {
		global $wpdb;
		$table           = $wpdb->prefix . 'baskerville_daily';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			day                  date      NOT NULL,
			traffic_total        int       NOT NULL DEFAULT 0,
			block_total          int       NOT NULL DEFAULT 0,
			challenge_total      int       NOT NULL DEFAULT 0,
			unique_ips_avg       int       NOT NULL DEFAULT 0,
			unique_sessions_avg  int       NOT NULL DEFAULT 0,
			immature_ratio_avg   float     NOT NULL DEFAULT 0,
			no_cookie_pct_avg    float     NOT NULL DEFAULT 0,
			incident_count       int       NOT NULL DEFAULT 0,
			peak_spike_factor    float     NOT NULL DEFAULT 0,
			countries_json       longtext  NULL,
			fingerprints_json    longtext  NULL,
			ua_json              longtext  NULL,
			asn_json             longtext  NULL,
			classifications_json longtext  NULL,
			known_bots_json      longtext  NULL,
			ai_traffic_json      longtext  NULL,
			PRIMARY KEY (day)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public function create_incidents_table(): void {
		global $wpdb;
		$table           = $wpdb->prefix . 'baskerville_incidents';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id             bigint(20)   NOT NULL AUTO_INCREMENT,
			started_at     datetime     NOT NULL,
			ended_at       datetime     NULL,
			status         varchar(20)  NOT NULL DEFAULT 'active',
			spike_type     varchar(20)  NOT NULL DEFAULT '',
			spike_factor   float        NOT NULL DEFAULT 0,
			no_cookie_mode varchar(20)  NOT NULL DEFAULT 'none',
			actions_json   longtext     NULL,
			reasoning      text         NULL,
			report_markdown longtext    NULL,
			ip_overlap_json longtext    NULL,
			PRIMARY KEY (id),
			KEY status (status),
			KEY started_at (started_at)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	public function create_reports_table(): void {
		global $wpdb;
		$table           = $wpdb->prefix . 'baskerville_reports';
		$charset_collate = $wpdb->get_charset_collate();

		$sql = "CREATE TABLE {$table} (
			id              bigint(20)   NOT NULL AUTO_INCREMENT,
			incident_id     bigint(20)   NULL,
			domain          varchar(255) NOT NULL DEFAULT '',
			created_at      datetime     NOT NULL,
			actions_json    longtext     NULL,
			reasoning       text         NULL,
			report_markdown longtext     NULL,
			applied         tinyint(1)   NOT NULL DEFAULT 0,
			PRIMARY KEY (id),
			KEY created_at (created_at),
			KEY incident_id (incident_id)
		) {$charset_collate};";

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		dbDelta( $sql );
	}

	// =========================================================================
	// Daily rollup
	// =========================================================================

	/**
	 * Aggregate yesterday's snapshots into a single wp_baskerville_daily row.
	 * Idempotent: skips if row already exists for that day.
	 * Called by baskerville_daily_rollup cron (runs once per day).
	 */
	public function run_daily_rollup(): void {
		global $wpdb;
		$snap_table  = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$daily_table = esc_sql( $wpdb->prefix . 'baskerville_daily' );
		$inc_table   = esc_sql( $wpdb->prefix . 'baskerville_incidents' );

		$yesterday = gmdate( 'Y-m-d', time() - 86400 );
		$day_start = $yesterday . ' 00:00:00';
		$day_end   = $yesterday . ' 23:59:59';

		// phpcs:disable WordPress.DB.DirectDatabaseQuery

		// Idempotent check.
		$exists = $wpdb->get_var( $wpdb->prepare(
			"SELECT 1 FROM {$daily_table} WHERE day = %s LIMIT 1",
			$yesterday
		) );
		if ( $exists ) {
			wpsec_log( "Baskerville Cloud: daily rollup — row already exists for {$yesterday}, skipping insert." );
			return;
		}

		// Load all snapshots for yesterday.
		$snaps = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$snap_table}
			 WHERE snapshot_at >= %s AND snapshot_at <= %s",
			$day_start, $day_end
		), ARRAY_A );

		if ( empty( $snaps ) ) {
			wpsec_log( "Baskerville Cloud: daily rollup — no snapshots found for {$yesterday} ({$day_start} to {$day_end}), skipping." );
			return; // nothing to roll up
		}

		wpsec_log( "Baskerville Cloud: daily rollup — found " . count( $snaps ) . " snapshots for {$yesterday}." );

		$n = count( $snaps );

		// Aggregate numeric fields.
		$traffic_total   = 0;
		$block_total     = 0;
		$challenge_total = 0;
		$unique_ips_sum  = 0;
		$unique_sess_sum = 0;
		$immature_sum    = 0.0;
		$no_cookie_sum   = 0.0;

		// Flat histogram sums.
		$histo_map = [
			'countries'       => 'countries_json',
			'fingerprints'    => 'fingerprints_json',
			'user_agents'     => 'ua_json',
			'asns'            => 'asn_json',
			'classifications' => 'classifications_json',
			'ai_traffic'      => 'ai_traffic_json',
		];
		$histo_sums     = array_fill_keys( array_keys( $histo_map ), [] );
		$known_bots_sum = [];

		foreach ( $snaps as $snap ) {
			$traffic_total   += (int) $snap['traffic_count'];
			$block_total     += (int) $snap['block_count'];
			$challenge_total += (int) $snap['challenge_count'];
			$unique_ips_sum  += (int) $snap['unique_ips'];
			$unique_sess_sum += (int) $snap['unique_sessions'];
			$immature_sum    += (float) $snap['immature_ratio'];
			$no_cookie_sum   += (float) $snap['no_cookie_pct'];

			foreach ( $histo_map as $field => $col ) {
				$data = json_decode( $snap[ $col ] ?? '{}', true ) ?: [];
				foreach ( $data as $k => $v ) {
					$histo_sums[ $field ][ $k ] = ( $histo_sums[ $field ][ $k ] ?? 0 ) + (int) $v;
				}
			}

			$kb = json_decode( $snap['known_bots_json'] ?? '{}', true ) ?: [];
			foreach ( $kb as $cat => $companies ) {
				foreach ( $companies as $company => $cnt ) {
					$known_bots_sum[ $cat ][ $company ] = ( $known_bots_sum[ $cat ][ $company ] ?? 0 ) + (int) $cnt;
				}
			}
		}

		// Sort histograms.
		foreach ( $histo_sums as &$h ) { arsort( $h ); }
		unset( $h );
		foreach ( $known_bots_sum as &$companies ) { arsort( $companies ); }
		unset( $companies );

		// Incident stats for yesterday.
		$inc_stats = $wpdb->get_row( $wpdb->prepare(
			"SELECT COUNT(*) AS incident_count, MAX(spike_factor) AS peak_spike_factor
			 FROM {$inc_table}
			 WHERE started_at >= %s AND started_at <= %s",
			$day_start, $day_end
		), ARRAY_A );

		$wpdb->insert( $daily_table, [
			'day'                  => $yesterday,
			'traffic_total'        => $traffic_total,
			'block_total'          => $block_total,
			'challenge_total'      => $challenge_total,
			'unique_ips_avg'       => (int) round( $unique_ips_sum / $n ),
			'unique_sessions_avg'  => (int) round( $unique_sess_sum / $n ),
			'immature_ratio_avg'   => round( $immature_sum / $n, 4 ),
			'no_cookie_pct_avg'    => round( $no_cookie_sum / $n, 2 ),
			'incident_count'       => (int) ( $inc_stats['incident_count'] ?? 0 ),
			'peak_spike_factor'    => (float) ( $inc_stats['peak_spike_factor'] ?? 0.0 ),
			'countries_json'       => wp_json_encode( $histo_sums['countries'] ) ?: '{}',
			'fingerprints_json'    => wp_json_encode( $histo_sums['fingerprints'] ) ?: '{}',
			'ua_json'              => wp_json_encode( array_slice( $histo_sums['user_agents'], 0, 20, true ) ) ?: '{}',
			'asn_json'             => wp_json_encode( $histo_sums['asns'] ) ?: '{}',
			'classifications_json' => wp_json_encode( $histo_sums['classifications'] ) ?: '{}',
			'known_bots_json'      => wp_json_encode( $known_bots_sum ) ?: '{}',
			'ai_traffic_json'      => wp_json_encode( $histo_sums['ai_traffic'] ) ?: '{}',
		], [ '%s', '%d', '%d', '%d', '%d', '%d', '%f', '%f', '%d', '%f', '%s', '%s', '%s', '%s', '%s', '%s', '%s' ] );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		wpsec_log( "Baskerville Cloud: daily rollup saved for {$yesterday} ({$n} snapshots)." );

		// Generate watchdog summary for the day we just rolled up.
		if ( $this->has_api_access() ) {
			$this->submit_watchdog( $yesterday );
		}
	}

	// =========================================================================
	// Watchdog
	// =========================================================================

	/**
	 * Build and submit a watchdog summary request for the given day.
	 * Fires after daily rollup. Async — job_id stored in wp_options, polled by maybe_analyze().
	 */
	private function submit_watchdog( string $for_day ): void {
		global $wpdb;
		$daily_table = esc_sql( $wpdb->prefix . 'baskerville_daily' );
		$inc_table   = esc_sql( $wpdb->prefix . 'baskerville_incidents' );

		wpsec_log( "Baskerville Cloud: submit_watchdog({$for_day}) called." );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$today_row = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$daily_table} WHERE day = %s", $for_day
		), ARRAY_A );

		if ( ! $today_row ) {
			wpsec_log( "Baskerville Cloud: submit_watchdog — no daily row for {$for_day}, cannot submit." );
			return;
		}

		$prev_day = gmdate( 'Y-m-d', strtotime( $for_day ) - 86400 );
		$prev_row = $wpdb->get_row( $wpdb->prepare(
			"SELECT * FROM {$daily_table} WHERE day = %s", $prev_day
		), ARRAY_A );

		$week_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$daily_table} WHERE day < %s ORDER BY day DESC LIMIT 7",
			$for_day
		), ARRAY_A );

		$inc_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT started_at, spike_type, spike_factor, reasoning
			 FROM {$inc_table}
			 WHERE DATE(started_at) = %s",
			$for_day
		), ARRAY_A );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$to_stats = function( ?array $row ): array {
			if ( ! $row ) {
				return [];
			}
			return [
				'traffic_total'      => (int) $row['traffic_total'],
				'block_total'        => (int) $row['block_total'],
				'challenge_total'    => (int) $row['challenge_total'],
				'incident_count'     => (int) $row['incident_count'],
				'peak_spike_factor'  => (float) $row['peak_spike_factor'],
				'immature_ratio_avg' => (float) $row['immature_ratio_avg'],
				'no_cookie_pct_avg'  => (float) $row['no_cookie_pct_avg'],
				'classifications'    => json_decode( $row['classifications_json'] ?? '{}', true ) ?: [],
				'ai_traffic'         => json_decode( $row['ai_traffic_json'] ?? '{}', true ) ?: [],
				'known_bots'         => json_decode( $row['known_bots_json'] ?? '{}', true ) ?: [],
				'countries'          => json_decode( $row['countries_json'] ?? '{}', true ) ?: [],
			];
		};

		// Build week average (numeric fields only).
		$week_avg = [];
		if ( ! empty( $week_rows ) ) {
			$wn     = count( $week_rows );
			$fields = [ 'traffic_total', 'block_total', 'challenge_total', 'incident_count', 'immature_ratio_avg', 'no_cookie_pct_avg' ];
			foreach ( $fields as $f ) {
				$week_avg[ $f ] = round( array_sum( array_column( $week_rows, $f ) ) / $wn, 2 );
			}
			$ai_sum = [];
			foreach ( $week_rows as $wr ) {
				$ai = json_decode( $wr['ai_traffic_json'] ?? '{}', true ) ?: [];
				foreach ( $ai as $k => $v ) {
					$ai_sum[ $k ] = ( $ai_sum[ $k ] ?? 0 ) + (int) $v;
				}
			}
			foreach ( $ai_sum as $k => &$v ) {
				$v = (int) round( $v / $wn );
			}
			unset( $v );
			arsort( $ai_sum );
			$week_avg['ai_traffic'] = $ai_sum;
		}

		$payload = [
			'license_key'     => (string) get_option( self::OPTION_LICENSE, '' ),
			'domain'          => parse_url( get_site_url(), PHP_URL_HOST ),
			'today'           => $to_stats( $today_row ),
			'yesterday'       => $to_stats( $prev_row ) ?: null,
			'week_avg'        => $week_avg ?: null,
			'incidents_today' => array_map( function( $r ) {
				return [
					'started_at'   => $r['started_at'],
					'spike_type'   => $r['spike_type'],
					'spike_factor' => (float) $r['spike_factor'],
					'reasoning'    => $r['reasoning'],
				];
			}, $inc_rows ),
		];

		$response = wp_remote_post(
			self::API_BASE . '/watchdog',
			[
				'timeout'  => 15,
				'blocking' => true,
				'headers'  => $this->api_headers(),
				'body'     => wp_json_encode( $payload ),
			]
		);

		if ( is_wp_error( $response ) ) {
			wpsec_log( 'Baskerville Cloud: watchdog submit failed — ' . $response->get_error_message() );
			return;
		}

		$http_code = wp_remote_retrieve_response_code( $response );
		$body      = json_decode( wp_remote_retrieve_body( $response ), true );
		$job_id    = $body['job_id'] ?? null;
		wpsec_log( "Baskerville Cloud: watchdog submit HTTP={$http_code} job_id=" . ( $job_id ?: 'null' ) );
		if ( $job_id ) {
			update_option( self::OPTION_WATCHDOG_JOB, [
				'job_id'       => $job_id,
				'submitted_at' => time(),
			] );
			wpsec_log( "Baskerville Cloud: watchdog job={$job_id}" );
		}
	}

	/**
	 * Poll for a pending watchdog job. Called from maybe_analyze() every 5 min.
	 * When ready, saves plain-text summary to wp_options.
	 */
	private function poll_watchdog_job(): void {
		$pending = get_option( self::OPTION_WATCHDOG_JOB );
		if ( ! $pending || empty( $pending['job_id'] ) ) {
			return;
		}

		if ( time() - (int) $pending['submitted_at'] > 7200 ) {
			delete_option( self::OPTION_WATCHDOG_JOB );
			return;
		}

		$response = wp_remote_get(
			self::API_BASE . '/report/' . $pending['job_id'],
			[ 'timeout' => 10, 'headers' => $this->api_headers() ]
		);

		if ( is_wp_error( $response ) ) {
			return;
		}

		$http_code = wp_remote_retrieve_response_code( $response );

		// 404 = job lost (pod restart cleared in-memory store). Clear the pending
		// option immediately so the daily retry can resubmit.
		if ( $http_code === 404 ) {
			delete_option( self::OPTION_WATCHDOG_JOB );
			wpsec_log( 'Baskerville Cloud: watchdog job not found (404), will retry.' );
			return;
		}

		if ( $http_code !== 200 ) {
			return; // transient error, keep retrying
		}

		$body   = json_decode( wp_remote_retrieve_body( $response ), true );
		$status = $body['status'] ?? 'pending';

		if ( $status === 'pending' ) {
			return;
		}

		delete_option( self::OPTION_WATCHDOG_JOB );

		if ( $status === 'ready' && ! empty( $body['summary'] ) ) {
			update_option( self::OPTION_WATCHDOG_TEXT, sanitize_textarea_field( $body['summary'] ) );
			update_option( self::OPTION_WATCHDOG_TIME, time() );
			update_option( self::OPTION_WATCHDOG_DATE, gmdate( 'Y-m-d', strtotime( '-1 day' ) ) );
			wpsec_log( 'Baskerville Cloud: watchdog summary saved.' );
		}
	}

	// =========================================================================
	// Dashboard widget
	// =========================================================================

	public function register_dashboard_widget(): void {
		wp_add_dashboard_widget(
			'baskerville_watchdog',
			__( 'Baskerville AI Watchdog', 'baskerville-ai-security' ),
			[ $this, 'render_dashboard_widget' ]
		);
	}

	public function render_dashboard_widget(): void {
		$summary = get_option( self::OPTION_WATCHDOG_TEXT, '' );
		$gen_at  = (int) get_option( self::OPTION_WATCHDOG_TIME, 0 );

		if ( empty( $summary ) ) {
			if ( ! $this->is_enabled() ) {
				printf(
					'<p><em>%s <a href="%s">%s</a>.</em></p>',
					esc_html__( 'Enter a license key in', 'baskerville-ai-security' ),
					esc_url( admin_url( 'admin.php?page=baskerville' ) ),
					esc_html__( 'Baskerville settings', 'baskerville-ai-security' )
				);
			} else {
				echo '<p><em>' . esc_html__( 'First summary will appear tomorrow morning after the nightly rollup.', 'baskerville-ai-security' ) . '</em></p>';
			}
			return;
		}

		// Parse status word from first line.
		$lines  = explode( "\n", trim( $summary ), 2 );
		$status = strtolower( trim( $lines[0] ) );
		$text   = trim( $lines[1] ?? $summary );

		$colors = [
			'quiet'   => '#00a32a',
			'warning' => '#dba617',
			'alert'   => '#d63638',
		];
		$color = $colors[ $status ] ?? '#666666';

		echo '<p><strong style="color:' . esc_attr( $color ) . '">&#9679; ' . esc_html( ucfirst( $status ) ) . '</strong></p>';
		echo '<p>' . nl2br( esc_html( $text ) ) . '</p>';

		if ( $gen_at ) {
			echo '<p style="color:#666;font-size:11px">' .
				esc_html( sprintf(
					/* translators: %s: human-readable time ago */
					__( 'Updated %s ago', 'baskerville-ai-security' ),
					human_time_diff( $gen_at )
				) ) .
				'</p>';
		}
	}

	// =========================================================================
	// Snapshot + daily cleanup (called by daily cron)
	// =========================================================================

	public function cleanup_snapshots(): void {
		global $wpdb;
		$snap_table  = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$daily_table = esc_sql( $wpdb->prefix . 'baskerville_daily' );
		$snap_cutoff = gmdate( 'Y-m-d H:i:s', time() - self::SNAPSHOT_RETENTION_H * 3600 );
		$daily_cutoff = gmdate( 'Y-m-d', time() - 365 * 86400 );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$snap_table} WHERE snapshot_at < %s",
			$snap_cutoff
		) );
		$wpdb->query( $wpdb->prepare(
			"DELETE FROM {$daily_table} WHERE day < %s",
			$daily_cutoff
		) );
		// phpcs:enable WordPress.DB.DirectDatabaseQuery
	}

	// =========================================================================
	// REST API — query interface
	// =========================================================================

	public function register_rest_routes(): void {
		register_rest_route( 'baskerville/v1', '/query', [
			'methods'             => 'POST',
			'callback'            => [ $this, 'rest_submit_query' ],
			'permission_callback' => function() { return current_user_can( 'manage_options' ); },
			'args'                => [
				'question' => [ 'required' => true, 'type' => 'string', 'sanitize_callback' => 'sanitize_textarea_field' ],
				'period'   => [ 'required' => false, 'type' => 'string', 'default' => '7d', 'sanitize_callback' => 'sanitize_text_field' ],
			],
		] );

		register_rest_route( 'baskerville/v1', '/query/(?P<job_id>[a-f0-9\-]+)', [
			'methods'             => 'GET',
			'callback'            => [ $this, 'rest_poll_query' ],
			'permission_callback' => function() { return current_user_can( 'manage_options' ); },
		] );
	}

	/**
	 * REST handler: POST /wp-json/baskerville/v1/query
	 * Builds payload from daily rollups and submits to backend.
	 */
	public function rest_submit_query( \WP_REST_Request $request ): \WP_REST_Response {
		if ( ! $this->has_api_access() ) {
			return new \WP_REST_Response( [ 'error' => 'Baskerville Cloud API not configured' ], 403 );
		}

		$question = $request->get_param( 'question' );
		$period   = $request->get_param( 'period' );

		$payload = $this->build_query_payload( $question, $period );

		$response = wp_remote_post(
			self::API_BASE . '/query',
			[
				'timeout'  => 15,
				'blocking' => true,
				'headers'  => $this->api_headers(),
				'body'     => wp_json_encode( $payload ),
			]
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_REST_Response( [ 'error' => $response->get_error_message() ], 502 );
		}

		$code = wp_remote_retrieve_response_code( $response );
		if ( $code !== 200 ) {
			return new \WP_REST_Response( [ 'error' => "Backend returned HTTP {$code}" ], 502 );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return new \WP_REST_Response( [ 'job_id' => $body['job_id'] ?? null ], 200 );
	}

	/**
	 * REST handler: GET /wp-json/baskerville/v1/query/{job_id}
	 * Proxies poll request to backend (keeps API secret server-side).
	 */
	public function rest_poll_query( \WP_REST_Request $request ): \WP_REST_Response {
		$job_id = sanitize_text_field( $request->get_param( 'job_id' ) );

		$response = wp_remote_get(
			self::API_BASE . '/report/' . $job_id,
			[ 'timeout' => 10, 'headers' => $this->api_headers() ]
		);

		if ( is_wp_error( $response ) ) {
			return new \WP_REST_Response( [ 'error' => $response->get_error_message() ], 502 );
		}

		$body = json_decode( wp_remote_retrieve_body( $response ), true );
		return new \WP_REST_Response( $body, wp_remote_retrieve_response_code( $response ) );
	}

	/**
	 * Build query payload from daily rollups for the requested period.
	 *
	 * @param string $question User's natural language question.
	 * @param string $period   "7d" | "30d" | "90d"
	 */
	private function build_query_payload( string $question, string $period ): array {
		global $wpdb;
		$daily_table = esc_sql( $wpdb->prefix . 'baskerville_daily' );
		$snap_table  = esc_sql( $wpdb->prefix . 'baskerville_snapshots' );
		$inc_table   = esc_sql( $wpdb->prefix . 'baskerville_incidents' );

		$days   = (int) rtrim( $period, 'd' );
		$days   = max( 1, min( 365, $days ) );
		$cutoff = gmdate( 'Y-m-d', time() - $days * 86400 );

		// phpcs:disable WordPress.DB.DirectDatabaseQuery
		$daily_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT * FROM {$daily_table} WHERE day >= %s ORDER BY day ASC",
			$cutoff
		), ARRAY_A );

		$inc_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT started_at, ended_at, spike_type, spike_factor, reasoning, actions_json
			 FROM {$inc_table}
			 WHERE DATE(started_at) >= %s ORDER BY started_at ASC",
			$cutoff
		), ARRAY_A );

		// Always include last 24h of snapshots aggregated into hourly buckets.
		// This gives the LLM fresh data even before the nightly daily rollup runs.
		$snap_cutoff = gmdate( 'Y-m-d H:i:s', time() - 86400 );
		$snap_rows   = $wpdb->get_results( $wpdb->prepare(
			"SELECT snapshot_at, traffic_count, block_count, challenge_count,
			        immature_ratio, no_cookie_pct,
			        ai_traffic_json, known_bots_json, classifications_json, countries_json
			 FROM {$snap_table}
			 WHERE snapshot_at >= %s
			 ORDER BY snapshot_at ASC",
			$snap_cutoff
		), ARRAY_A );

		// Direct today totals from wp_baskerville_stats — accurate even when snapshots are sparse.
		$stats_table   = esc_sql( $wpdb->prefix . 'baskerville_stats' );
		$today_start   = gmdate( 'Y-m-d' ) . ' 00:00:00';
		// Use last-24h window to match the Live Bot Dashboard "Blocked Today" counter.
		$last24h_start = gmdate( 'Y-m-d H:i:s', time() - 86400 );
		$today_totals  = $wpdb->get_row( $wpdb->prepare(
			"SELECT
				COUNT(*) AS traffic_total,
				SUM(CASE WHEN classification IN ('bad_bot','ai_bot','ai_bot_unverified') THEN 1 ELSE 0 END) AS block_total,
				COUNT(DISTINCT CASE WHEN classification IN ('bad_bot','ai_bot','ai_bot_unverified') THEN ip END) AS blocked_unique_ips,
				SUM(CASE WHEN event_type = 'block' THEN 1 ELSE 0 END) AS firewall_block_total,
				SUM(CASE WHEN classification IN ('bot','bad_bot') AND event_type != 'block' THEN 1 ELSE 0 END) AS challenge_total,
				COUNT(DISTINCT ip) AS unique_ips
			 FROM {$stats_table}
			 WHERE created_at >= %s",
			$last24h_start
		), ARRAY_A );

		// Top countries for today (last 24h).
		$today_countries_rows = $wpdb->get_results( $wpdb->prepare(
			"SELECT COALESCE(NULLIF(country_code,''),'XX') AS country, COUNT(*) AS cnt
			 FROM {$stats_table}
			 WHERE created_at >= %s
			 GROUP BY country_code
			 ORDER BY cnt DESC
			 LIMIT 10",
			$last24h_start
		), ARRAY_A );
		$today_countries = [];
		foreach ( $today_countries_rows as $r ) {
			$today_countries[ $r['country'] ] = (int) $r['cnt'];
		}
		// phpcs:enable WordPress.DB.DirectDatabaseQuery

		$rollups = array_map( function( $row ) {
			return [
				'day'                => $row['day'],
				'traffic_total'      => (int) $row['traffic_total'],
				'block_total'        => (int) $row['block_total'],
				'challenge_total'    => (int) $row['challenge_total'],
				'incident_count'     => (int) $row['incident_count'],
				'peak_spike_factor'  => (float) $row['peak_spike_factor'],
				'immature_ratio_avg' => (float) $row['immature_ratio_avg'],
				'no_cookie_pct_avg'  => (float) $row['no_cookie_pct_avg'],
				'ai_traffic'         => json_decode( $row['ai_traffic_json'] ?? '{}', true ) ?: [],
				'known_bots'         => json_decode( $row['known_bots_json'] ?? '{}', true ) ?: [],
				'classifications'    => json_decode( $row['classifications_json'] ?? '{}', true ) ?: [],
				'countries'          => json_decode( $row['countries_json'] ?? '{}', true ) ?: [],
			];
		}, $daily_rows );

		$incidents = array_map( function( $row ) {
			return [
				'started_at'   => $row['started_at'],
				'ended_at'     => $row['ended_at'],
				'spike_type'   => $row['spike_type'],
				'spike_factor' => (float) $row['spike_factor'],
				'reasoning'    => $row['reasoning'],
				'actions_json' => $row['actions_json'],
			];
		}, $inc_rows );

		// Aggregate snapshots into hourly buckets, merging JSON histograms.
		$hourly = [];
		foreach ( $snap_rows as $row ) {
			$hour = substr( $row['snapshot_at'], 0, 13 ) . ':00'; // YYYY-MM-DD HH:00
			if ( ! isset( $hourly[ $hour ] ) ) {
				$hourly[ $hour ] = [
					'hour'           => $hour,
					'traffic'        => 0,
					'blocks'         => 0,
					'challenges'     => 0,
					'immature_ratio' => 0.0,
					'no_cookie_pct'  => 0.0,
					'_count'         => 0,
					'ai_traffic'     => [],
					'known_bots'     => [],
					'classifications' => [],
					'countries'      => [],
				];
			}
			$h = &$hourly[ $hour ];
			$h['traffic']    += (int) $row['traffic_count'];
			$h['blocks']     += (int) $row['block_count'];
			$h['challenges'] += (int) $row['challenge_count'];
			$h['immature_ratio'] += (float) $row['immature_ratio'];
			$h['no_cookie_pct']  += (float) $row['no_cookie_pct'];
			$h['_count']++;

			// Merge flat histograms (sum counts per key).
			foreach ( [ 'ai_traffic', 'classifications', 'countries' ] as $key ) {
				$data = json_decode( $row[ $key . '_json' ] ?? '{}', true ) ?: [];
				foreach ( $data as $k => $v ) {
					$h[ $key ][ $k ] = ( $h[ $key ][ $k ] ?? 0 ) + (int) $v;
				}
			}
			// Merge nested known_bots: category → company → count.
			$kb = json_decode( $row['known_bots_json'] ?? '{}', true ) ?: [];
			foreach ( $kb as $cat => $companies ) {
				foreach ( $companies as $company => $count ) {
					$h['known_bots'][ $cat ][ $company ] = ( $h['known_bots'][ $cat ][ $company ] ?? 0 ) + (int) $count;
				}
			}
			unset( $h );
		}

		$recent_snapshots = [];
		foreach ( $hourly as &$h ) {
			if ( $h['_count'] > 0 ) {
				$h['immature_ratio'] = round( $h['immature_ratio'] / $h['_count'], 3 );
				$h['no_cookie_pct']  = round( $h['no_cookie_pct']  / $h['_count'], 3 );
			}
			unset( $h['_count'] );
			// PHP encodes empty arrays as [] but FastAPI expects {} for dict fields.
			foreach ( [ 'ai_traffic', 'known_bots', 'classifications', 'countries' ] as $dict_field ) {
				if ( empty( $h[ $dict_field ] ) ) {
					$h[ $dict_field ] = new stdClass();
				}
			}
			$recent_snapshots[] = $h;
		}
		unset( $h );

		return [
			'license_key'      => (string) get_option( self::OPTION_LICENSE, '' ),
			'domain'           => parse_url( get_site_url(), PHP_URL_HOST ),
			'question'         => $question,
			'period'           => $period,
			'today_totals'     => $today_totals ? [
				'traffic_total'       => (int) $today_totals['traffic_total'],
				'block_total'         => (int) $today_totals['block_total'],
				'blocked_unique_ips'  => (int) $today_totals['blocked_unique_ips'],
				'firewall_block_total'=> (int) $today_totals['firewall_block_total'],
				'challenge_total'     => (int) $today_totals['challenge_total'],
				'unique_ips'          => (int) $today_totals['unique_ips'],
				'countries'           => $today_countries ?: new stdClass(),
				'note'                => 'Last-24h counts matching live dashboard. block_total = detected bad-bot requests; firewall_block_total = requests with explicit 403 firewall block.',
			] : null,
			'daily_rollups'    => $rollups,
			'recent_snapshots' => $recent_snapshots,
			'incidents'        => $incidents,
		];
	}

	// =========================================================================
	// Helpers
	// =========================================================================

	public function is_enabled(): bool {
		return ! empty( get_option( self::OPTION_LICENSE, '' ) );
	}

	/**
	 * Whether the Cloud API secret is configured (required for query + watchdog endpoints).
	 */
	private function has_api_access(): bool {
		return ! empty( get_option( self::OPTION_API_SECRET, '' ) );
	}
}
