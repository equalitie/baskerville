<?php

class Baskerville_Firewall
{
	/** @var Baskerville_Core */
	private $core;

	/** @var Baskerville_Stats */
	private $stats;

	/** @var Baskerville_AI_UA */
	private $aiua;

	public function __construct(Baskerville_Core $core, Baskerville_Stats $stats, Baskerville_AI_UA $aiua) {
		$this->core = $core;
		$this->stats = $stats;
		$this->aiua = $aiua;
	}

	/* ===== Ban cache (no DB) ===== */
	private function get_ban(string $ip): ?array {
		$v = $this->core->fc_get("ban:{$ip}");
		return is_array($v) ? $v : null;
	}

	private function set_ban(string $ip, string $reason, int $ttl, array $meta = []): void {
		$payload = array_merge(['reason' => $reason, 'until' => time() + $ttl], $meta);
		$this->core->fc_set("ban:{$ip}", $payload, $ttl);
	}

	/* ===== One-shot DB logging gate for blocks ===== */
	private function blocklog_once(string $ip, string $reason, array $evaluation, array $classification, string $ua, int $gate_ttl = 600): void {
		$sig = md5($reason);
		$k   = "blocklog:{$ip}:{$sig}";
		if ($this->core->fc_get($k)) return; // already logged recently
		$this->core->fc_set($k, 1, $gate_ttl);
		$this->insert_block_row($ip, $evaluation, $classification, $ua, $reason);
	}

	/**
	 * Insert block event row into database.
	 *
	 * Direct database queries are required for real-time firewall blocking.
	 * Caching is not applicable as blocks must be logged immediately.
	 *
	 * @param string $ip IP address being blocked.
	 * @param array  $evaluation Evaluation data.
	 * @param array  $classification Classification data.
	 * @param string $ua User agent string.
	 * @param string $reason Block reason.
	 * @return void
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	private function insert_block_row(string $ip, array $evaluation, array $classification, string $ua, string $reason): void {
		global $wpdb;
		$table     = $wpdb->prefix . 'baskerville_stats';
		$cookie_id = $this->core->get_cookie_id() ?: '';
		$visit_key = $this->stats->make_visit_key($ip, $cookie_id);

		// Get country code for GeoIP analytics
		$country_code = $this->core->get_country_by_ip($ip);

		$ok = $wpdb->insert(
			$table,
			[
				'visit_key'             => $visit_key,
				'ip'                    => $ip,
				'country_code'          => $country_code,
				'baskerville_id'        => $cookie_id,
				'timestamp_utc'         => current_time('mysql', true),
				'score'                 => (int)($evaluation['score'] ?? 0),
				'classification'        => (string)($classification['classification'] ?? 'unknown'),
				'user_agent'            => $ua,
				'evaluation_json'       => wp_json_encode($evaluation),
				'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
				'classification_reason' => (string)($classification['reason'] ?? ''),
				'block_reason'          => mb_substr($reason, 0, 120),
				'event_type'            => 'block',
				'had_fp'                => 0,
			],
			['%s','%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%d']
		);

		if ($ok === false) {
			// error_log('Baskerville: insert_block_row failed - ' . $wpdb->last_error);
		}
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery

	/* ===== send 403 and stop ===== */
	private function send_403_and_exit(array $meta): void {
		// Check if bot protection is enabled in settings (default: true)
		$options = get_option('baskerville_settings', array());
		$ban_enabled = !isset($options['bot_protection_enabled']) || $options['bot_protection_enabled'];

		if (!$ban_enabled) {
			// If bans are disabled, just return and allow the request to continue
			return;
		}

		if (!headers_sent()) {
			status_header(403);
			nocache_headers();
			header('Content-Type: text/plain; charset=UTF-8');
			if (!empty($meta['reason'])) header('X-Baskerville-Reason: ' . $meta['reason']);
			if (isset($meta['score']))   header('X-Baskerville-Score: ' . (int)$meta['score']);
			if (!empty($meta['cls']))    header('X-Baskerville-Class: ' . $meta['cls']);
			if (!empty($meta['until'])) {
				$until = (int)$meta['until'];
				header('X-Baskerville-Until: ' . gmdate('c', $until));
				$retry = max(1, $until - time());
				header('Retry-After: ' . $retry);
			}
		}

		// Show specific message based on ban reason (no translations - runs before init)
		$reason = $meta['reason'] ?? '';
		if (strpos($reason, 'no-cookie-burst') === 0) {
			echo 'Forbidden - Too many requests without session cookie';
		} elseif (strpos($reason, 'nojs-burst') === 0) {
			echo 'Forbidden - Too many requests without JavaScript';
		} elseif (strpos($reason, 'nojs-burst') === 0) {
			echo 'Forbidden - Non-browser client rate limit exceeded';
		} elseif (strpos($reason, 'ai-bot') === 0) {
			echo 'Forbidden - AI bot detected';
		} elseif (strpos($reason, 'cached-ban') === 0) {
			echo 'Forbidden - IP temporarily banned';
		} else {
			echo 'Forbidden - Bot detected';
		}
		echo "\n";
		exit;
	}

	/* ===== send 403 for GeoIP blocking - always blocks regardless of ban_bots_403 setting ===== */
	private function send_403_geo_and_exit(array $meta): void {
		if (!headers_sent()) {
			status_header(403);
			nocache_headers();
			header('Content-Type: text/plain; charset=UTF-8');
			if (!empty($meta['reason'])) header('X-Baskerville-Reason: ' . $meta['reason']);
			if (isset($meta['score']))   header('X-Baskerville-Score: ' . (int)$meta['score']);
			if (!empty($meta['cls']))    header('X-Baskerville-Class: ' . $meta['cls']);
			if (!empty($meta['until'])) {
				$until = (int)$meta['until'];
				header('X-Baskerville-Until: ' . gmdate('c', $until));
				$retry = max(1, $until - time());
				header('Retry-After: ' . $retry);
			}
		}
		echo "Forbidden - Access from this country is restricted\n";
		exit;
	}

	public function pre_db_firewall(): void {
		$ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));

		if ($ip === '') return;

		// Get options once
		$options = get_option('baskerville_settings', array());

		// Check Master Switch - if disabled, all blocking is off (only logging)
		$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
		if (!$master_enabled) {
			return; // Master switch OFF - no blocking, only logging
		}

		// IP whitelist — allow through
		if ($this->core->is_whitelisted_ip($ip)) {
			return;
		}

		// Check if this is WordPress admin area or login page - always allow
		$request_uri = sanitize_text_field(wp_unslash($_SERVER['REQUEST_URI'] ?? ''));
		$is_admin_area = (strpos($request_uri, '/wp-admin/') !== false ||
						 strpos($request_uri, '/wp-login.php') !== false ||
						 is_admin());

		if ($is_admin_area) {
			return;
		}

		// Check if this is an API request (REST, GraphQL, webhooks, etc.)
		$is_api = $this->core->is_api_request();
		if ($is_api) {
			// API requests: apply rate limiting only, no 403 bans
			$rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;

			if ($rate_limit_enabled) {
				$max_requests = isset($options['api_rate_limit_requests']) ? (int)$options['api_rate_limit_requests'] : 100;
				$window_sec = isset($options['api_rate_limit_window']) ? (int)$options['api_rate_limit_window'] : 60;

				$key = "api_global_ratelimit:{$ip}";
				$count = $this->core->fc_inc_in_window($key, $window_sec);

				if ($count > $max_requests) {
					// Send 429 Too Many Requests
					http_response_code(429);
					header('Retry-After: ' . $window_sec);
					header('Content-Type: application/json');

					echo wp_json_encode([
						'error'       => 'rate_limit_exceeded',
						'message'     => sprintf( 'Rate limit exceeded. Maximum %d requests per %d seconds.', $max_requests, $window_sec),
						'retry_after' => $window_sec
					]);
					exit;
				}
			}

			// API requests bypass firewall, only rate limiting applies
			return;
		}

		// GeoIP country ban check (applies to frontend requests only, NOT wp-admin)
		$geoip_enabled = isset($options['geoip_enabled']) ? $options['geoip_enabled'] : false;
		$mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';

		// Only process GeoIP checks if enabled AND not in "allow_all" mode
		if ($geoip_enabled && $mode !== 'allow_all') {
			$country = $this->core->get_country_by_ip($ip);

			if ($country) {
				$should_block = false;
				$reason_prefix = '';
				$country_list_str = '';

				if ($mode === 'whitelist') {
					// Whitelist mode: block if country is NOT in the list
					$country_list_str = isset($options['whitelist_countries']) ? $options['whitelist_countries'] : '';
					if (!empty($country_list_str)) {
						$whitelist_countries = array_map('trim', array_map('strtoupper', explode(',', $country_list_str)));
						$should_block = !in_array($country, $whitelist_countries, true);
						$reason_prefix = 'geo-whitelist-blocked';
					}
				} elseif ($mode === 'blacklist') {
					// Blacklist mode: block if country IS in the list
					$country_list_str = isset($options['blacklist_countries']) ? $options['blacklist_countries'] : '';
					if (!empty($country_list_str)) {
						$blacklist_countries = array_map('trim', array_map('strtoupper', explode(',', $country_list_str)));
						$should_block = in_array($country, $blacklist_countries, true);
						$reason_prefix = 'geo-blacklist-blocked';
					}
				}

				if ($should_block) {
					$ua = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
					$headers = [
						'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
						'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
						'user_agent'      => $ua,
						'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
						'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
					];

					$evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
					$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
					$reason = "{$reason_prefix}:{$country}";
					$ttl = (int) get_option('baskerville_ban_ttl_sec', 600);

					$this->set_ban($ip, $reason, $ttl, [
						'score' => (int)($evaluation['score'] ?? 0),
						'cls'   => 'geo-banned',
					]);
					$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);

					// Use dedicated GeoIP blocking function - always blocks regardless of ban_bots_403 setting
					$this->send_403_geo_and_exit([
						'reason' => $reason,
						'score'  => $evaluation['score'] ?? null,
						'cls'    => 'geo-banned',
						'until'  => time() + $ttl,
					]);
				}
			}
		}

		// AI Bot Company Blocking Check
		$ai_bot_control_enabled = isset($options['ai_bot_control_enabled']) ? $options['ai_bot_control_enabled'] : true;
		$ai_bot_mode = isset($options['ai_bot_blocking_mode']) ? $options['ai_bot_blocking_mode'] : 'allow_all';
		if ($ai_bot_control_enabled && $ai_bot_mode !== 'allow_all') {
			$ua = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
			$headers = [
				'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
				'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
				'user_agent'      => $ua,
				'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
				'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
			];

			$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);

			// Check if this is an AI bot
			if (isset($classification['classification']) && $classification['classification'] === 'ai_bot') {
				$company = $this->aiua->get_ai_bot_company($ua);
				$should_block = false;
				$reason_prefix = '';

				if ($ai_bot_mode === 'block_all') {
					// Block all AI bots mode: block ALL AI bots regardless of company
					$should_block = true;
					$reason_prefix = 'ai-bot-block-all';
				} elseif ($ai_bot_mode === 'whitelist') {
					// Whitelist mode: block if company is NOT in the list
					$company_list_str = isset($options['whitelist_ai_companies']) ? $options['whitelist_ai_companies'] : '';
					if (!empty($company_list_str)) {
						$whitelist_companies = array_map('trim', explode(',', $company_list_str));
						$should_block = !in_array($company, $whitelist_companies, true);
						$reason_prefix = 'ai-bot-whitelist-blocked';
					}
				} elseif ($ai_bot_mode === 'blacklist') {
					// Blacklist mode: block if company IS in the list
					$company_list_str = isset($options['blacklist_ai_companies']) ? $options['blacklist_ai_companies'] : '';
					if (!empty($company_list_str)) {
						$blacklist_companies = array_map('trim', explode(',', $company_list_str));
						$should_block = in_array($company, $blacklist_companies, true);
						$reason_prefix = 'ai-bot-blacklist-blocked';
					}
				}

				if ($should_block) {
					$evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
					$reason = "{$reason_prefix}:{$company}";
					$ttl = (int) get_option('baskerville_ban_ttl_sec', 600);

					$this->set_ban($ip, $reason, $ttl, [
						'score' => (int)($evaluation['score'] ?? 0),
						'cls'   => 'ai-bot-banned',
					]);
					$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);

					// Block AI bot
					$this->send_403_and_exit([
						'reason' => $reason,
						'score'  => $evaluation['score'] ?? null,
						'cls'    => 'ai-bot-banned',
						'until'  => time() + $ttl,
					]);
				}
			}
		}

		// Check if this is a public HTML page (GET/HEAD with HTML Accept header)
		// Burst protection and bot detection only apply to public HTML pages
		if (!$this->core->is_public_html_request()) {
			return;
		}

		// If there's a valid FP cookie — suppress no-JS triggers
		$fp_cookie = $this->core->read_fp_cookie();
		if ($fp_cookie) {
			$this->core->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180));
		}

		// Headers for server-side heuristics
		$ua = sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? ''));
		$headers = [
			'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
			'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
			'user_agent'      => $ua,
			'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
			'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
		];

		// 0) Already banned?
		if ($ban = $this->get_ban($ip)) {
			// if it's a verified crawler — remove the ban
			if (($ban['cls'] ?? '') === 'verified_bot') {
				$this->core->fc_delete("ban:{$ip}");
			// if it's a geo-ban, check if GeoIP blocking is still enabled
			// Check both cls field and reason prefix to catch all geo-bans
			} elseif (($ban['cls'] ?? '') === 'geo-banned' || strpos($ban['reason'] ?? '', 'geo-') === 0) {
				// Get fresh options to check current GeoIP settings (avoid stale cache)
				$fresh_options = get_option('baskerville_settings', array());
				$geoip_still_enabled = isset($fresh_options['geoip_enabled']) ? $fresh_options['geoip_enabled'] : false;
				$geoip_mode = isset($fresh_options['geoip_mode']) ? $fresh_options['geoip_mode'] : 'allow_all';
				// If GeoIP is now disabled or set to allow_all, clear the geo-ban and allow request
				if (!$geoip_still_enabled || $geoip_mode === 'allow_all') {
					$this->core->fc_delete("ban:{$ip}");
					// Clear all burst counters and give grace period to get cookie
					$this->core->fc_delete("nocookie_burst:{$ip}");
					$this->core->fc_delete("nojs_cnt:{$ip}");
					// Set grace period flag - allows IP to bypass burst protection temporarily (60 seconds)
					// This gives the user time to load the page and receive the Baskerville cookie
					$this->core->fc_set("geo_grace:{$ip}", 1, 60);
					// Skip all remaining firewall checks - geo-ban was just cleared
					return;
				} else {
					// GeoIP still active - enforce the ban
					$evaluation = ['score' => (int)($ban['score'] ?? 0), 'reasons' => ['cached-ban']];
					$classification = [
						'classification' => (string)($ban['cls'] ?? 'bot'),
						'reason'         => (string)($ban['reason'] ?? 'cached-ban'),
					];
					$this->blocklog_once(
						$ip,
						(string)($ban['reason'] ?? 'cached-ban'),
						$evaluation,
						$classification,
						$ua,
						600
					);
					$this->send_403_geo_and_exit($ban);
				}
			} else {
				$evaluation = ['score' => (int)($ban['score'] ?? 0), 'reasons' => ['cached-ban']];
				$classification = [
					'classification' => (string)($ban['cls'] ?? 'bot'),
					'reason'         => (string)($ban['reason'] ?? 'cached-ban'),
				];
				$this->blocklog_once(
					$ip,
					(string)($ban['reason'] ?? 'cached-ban'),
					$evaluation,
					$classification,
					$ua,
					600
				);
				$this->send_403_and_exit($ban);
			}
		}

		// Helpers
		$looks_like_browser = $this->aiua->looks_like_browser_ua($ua);
		$vc                 = $this->aiua->verify_crawler_ip($ip, $ua);

		// Check if verified crawlers should be allowed (default: true)
		$allow_verified = !isset($options['allow_verified_crawlers']) || $options['allow_verified_crawlers'];
		$verified_crawler = $allow_verified && ($vc['claimed'] && $vc['verified']);

		// Check if has valid session cookie on arrival
		$has_valid_cookie = $this->core->arrival_has_valid_cookie();

		// Check if burst protection is enabled (default: true)
		// Use new burst_protection_enabled field, fallback to legacy enable_burst_protection
		$burst_enabled = isset($options['burst_protection_enabled'])
			? $options['burst_protection_enabled']
			: (!isset($options['enable_burst_protection']) || $options['enable_burst_protection']);

		// Check for grace period (after geo-ban was cleared, user needs time to get cookie)
		$has_grace_period = (bool) $this->core->fc_get("geo_grace:{$ip}");

		// 1) no-cookie burst: ANY IP without valid cookie making too many requests
		if ($burst_enabled && !$has_valid_cookie && !$verified_crawler && !$has_grace_period) {
			$window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
			$threshold  = (int) get_option('baskerville_nocookie_threshold', 10);
			$cnt        = $this->core->fc_inc_in_window("nocookie_burst:{$ip}", $window_sec);

			if ($cnt > $threshold) {
				$evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
				$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);

				$reason = "no-cookie-burst>{$threshold}/{$window_sec}s";
				$ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

				$this->set_ban($ip, $reason, $ttl, [
					'score' => (int)($evaluation['score'] ?? 0),
					'cls'   => (string)($classification['classification'] ?? 'bot'),
				]);
				$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
				$this->send_403_and_exit([
					'reason' => $reason,
					'score'  => $evaluation['score'] ?? null,
					'cls'    => $classification['classification'] ?? null,
					'until'  => time() + $ttl,
				]);
			}
		}

		// 3) no-JS burst: count only pages for which we haven't seen FP "recently"
		$fp_seen_recent = (bool) $this->core->fc_get("fp_seen_ip:{$ip}");
		if ($burst_enabled && !$fp_seen_recent && !$verified_crawler && !$has_grace_period) {
			$window_sec = (int) get_option('baskerville_nojs_window_sec', 60);
			$threshold  = (int) get_option('baskerville_nojs_threshold', 20);
			$cnt        = $this->core->fc_inc_in_window("nojs_cnt:{$ip}", $window_sec);

			if ($cnt > $threshold) {
				// Evaluation by server headers (without JS)
				$evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
				$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);

				$reason = "nojs-burst>{$threshold}/{$window_sec}s";
				$ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

				$this->set_ban($ip, $reason, $ttl, [
					'score' => (int)($evaluation['score'] ?? 0),
					'cls'   => (string)($classification['classification'] ?? 'unknown'),
				]);
				$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
				$this->send_403_and_exit([
					'reason' => $reason,
					'score'  => $evaluation['score'] ?? null,
					'cls'    => $classification['classification'] ?? null,
					'until'  => time() + $ttl,
				]);
			}
		}

		// 4) Non-browser UA (and not a "good" crawler): fast burst block
		$ua_l = strtolower($ua);
		$nonbrowser_signatures = [
			'curl','wget','python-requests','go-http-client','httpie','libcurl',
			'java','okhttp','node-fetch','axios','aiohttp','urllib','postmanruntime',
			'insomnia','restsharp','powershell','httpclient','http.rb','ruby','perl',
			'traefik','kube-probe','healthcheck','pingdom','datadog','sumologic'
		];
		$is_nonbrowser = false;
		foreach ($nonbrowser_signatures as $sig) {
			if (strpos($ua_l, $sig) !== false) { $is_nonbrowser = true; break; }
		}

		// Also flag suspiciously short or simple UA strings (likely custom bots)
		if (!$is_nonbrowser && strlen($ua) > 0 && strlen($ua) < 30) {
			// Check if it looks like a browser (contains mozilla, chrome, safari, firefox, edge, opera)
			$browser_keywords = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'msie', 'trident'];
			$has_browser_keyword = false;
			foreach ($browser_keywords as $keyword) {
				if (strpos($ua_l, $keyword) !== false) {
					$has_browser_keyword = true;
					break;
				}
			}
			// If UA is short AND doesn't contain browser keywords, it's suspicious
			if (!$has_browser_keyword) {
				$is_nonbrowser = true;
			}
		}

		if ($burst_enabled && $is_nonbrowser && !$verified_crawler && !$has_grace_period) {
			$window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
			$threshold  = (int) get_option('baskerville_nocookie_threshold', 10);

			// "does it have a valid cookie on entry?" — use the core public method
			$no_cookie  = !$this->core->arrival_has_valid_cookie();
			$key        = $no_cookie ? "nbua_nocookie_cnt:{$ip}" : "nbua_cnt:{$ip}";
			$cnt        = $this->core->fc_inc_in_window($key, $window_sec);

			if ($no_cookie && $cnt > $threshold) {
				$evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
				$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
				$reason         = "nonbrowser-ua-burst>{$threshold}/{$window_sec}s";
				$ttl            = (int) get_option('baskerville_ban_ttl_sec', 600);

				$this->set_ban($ip, $reason, $ttl, [
					'score' => (int)($evaluation['score'] ?? 0),
					'cls'   => (string)($classification['classification'] ?? 'bot'),
				]);
				$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
				$this->send_403_and_exit([
					'reason' => $reason,
					'score'  => $evaluation['score'] ?? null,
					'cls'    => $classification['classification'] ?? null,
					'until'  => time() + $ttl,
				]);
			}
			// threshold not exceeded yet — allow through
		}

		// 5) High risk from server headers + doesn't look like a browser
		$evaluation     = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);
		$classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);
		$risk           = (int)($evaluation['score'] ?? 0);

		if ($burst_enabled && ($classification['classification'] ?? '') === 'bad_bot' && !$verified_crawler) {
			$window_sec = (int) get_option('baskerville_nocookie_window_sec', 60);
			$threshold  = (int) get_option('baskerville_nocookie_threshold', 10);
			$cnt        = $this->core->fc_inc_in_window("badbot_cnt:{$ip}", $window_sec);

			// Log to stats if >= 3 requests (but don't ban yet)
			// Use gate to log only once per IP per window
			if ($cnt >= 3) {
				$gate_key = "badbot_logged:{$ip}";
				if (!$this->core->fc_get($gate_key)) {
					$this->core->fc_set($gate_key, 1, $window_sec);
					$cookie_id = $this->core->get_cookie_id();
					$this->stats->save_visit_stats(
						$ip,
						$cookie_id ?? '',
						$evaluation,
						$classification,
						$ua,
						'firewall',
						null,
						null  // Not banned yet
					);
				}
			}

			// Ban only if threshold exceeded
			if ($cnt > $threshold) {
				$reason = 'classified-bad-bot-burst';
				$ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

				$this->set_ban($ip, $reason, $ttl, [
					'score' => $risk,
					'cls'   => (string)($classification['classification'] ?? 'bot'),
				]);
				$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
				$this->send_403_and_exit([
					'reason' => $reason,
					'score'  => $risk,
					'cls'    => $classification['classification'] ?? null,
					'until'  => time() + $ttl,
				]);
			}
		} elseif ($risk >= 85 && !$looks_like_browser && !$verified_crawler) {
			// very suspicious — can block immediately
			$reason = 'high-risk-nonbrowser';
			$ttl    = (int) get_option('baskerville_ban_ttl_sec', 600);

			$this->set_ban($ip, $reason, $ttl, [
				'score' => $risk,
				'cls'   => (string)($classification['classification'] ?? 'bot'),
			]);
			$this->blocklog_once($ip, $reason, $evaluation, $classification, $ua);
			$this->send_403_and_exit([
				'reason' => $reason,
				'score'  => $risk,
				'cls'    => $classification['classification'] ?? null,
				'until'  => time() + $ttl,
			]);
		}

		// 6) (optional) additional policies can be added here
	}
}
