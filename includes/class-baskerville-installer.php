<?php

class Baskerville_Installer {

	/**
	 * Called upon plugin activation.
	 */
	public static function activate() {
		// Create helper objects for working with DB schema
		$core  = new Baskerville_Core();
		$aiua  = new Baskerville_AI_UA($core);
		$stats = new Baskerville_Stats($core, $aiua);

		// Statistics table + schema upgrade
		// IMPORTANT: method maybe_upgrade_schema must be public in Baskerville_Stats.
		$stats->create_stats_table();
		if (method_exists($stats, 'maybe_upgrade_schema')) {
			$stats->maybe_upgrade_schema();
		}

		// Default options (don't overwrite if already exist)
		if (get_option('baskerville_retention_days') === false) {
			add_option('baskerville_retention_days', BASKERVILLE_DEFAULT_RETENTION_DAYS);
		}
		if (get_option('baskerville_cookie_secret') === false) {
			add_option('baskerville_cookie_secret', bin2hex(random_bytes(32)));
		}

		if (get_option('baskerville_nocookie_window_sec') === false)  add_option('baskerville_nocookie_window_sec', 60);
		if (get_option('baskerville_nocookie_threshold') === false)   add_option('baskerville_nocookie_threshold', 10);
		if (get_option('baskerville_nocookie_ban_minutes') === false) add_option('baskerville_nocookie_ban_minutes', 10);

		if (get_option('baskerville_nojs_window_sec') === false)      add_option('baskerville_nojs_window_sec', 60);
		if (get_option('baskerville_nojs_threshold') === false)       add_option('baskerville_nojs_threshold', 20);
		if (get_option('baskerville_fp_seen_ttl_sec') === false)      add_option('baskerville_fp_seen_ttl_sec', 180);
		if (get_option('baskerville_ban_ttl_sec') === false)          add_option('baskerville_ban_ttl_sec', 600);
		if (get_option('baskerville_fp_attach_window_sec') === false) add_option('baskerville_fp_attach_window_sec', 180);
		if (get_option('baskerville_ip_whitelist') === false)         add_option('baskerville_ip_whitelist', '');
		if (get_option('baskerville_honeypot_ban_ttl') === false)     add_option('baskerville_honeypot_ban_ttl', 86400); // 24 hours

		// Default honeypot and logging settings
		$settings = get_option('baskerville_settings', array());
		$needs_update = false;
		if (!isset($settings['honeypot_enabled'])) {
			$settings['honeypot_enabled'] = true; // Enabled by default
			$needs_update = true;
		}
		if (!isset($settings['honeypot_ban'])) {
			$settings['honeypot_ban'] = true; // Ban by default
			$needs_update = true;
		}
		// Set default log_mode only if not already set (preserve existing user choice)
		if (!isset($settings['log_mode'])) {
			$settings['log_mode'] = 'database'; // Database logging by default
			$needs_update = true;
		}
		if ($needs_update) {
			update_option('baskerville_settings', $settings);
		}

		// Cron for regular statistics cleanup
		if (!wp_next_scheduled('baskerville_cleanup_stats')) {
			wp_schedule_event(time(), 'daily', 'baskerville_cleanup_stats');
		}

		// Cron for expired cache file cleanup
		if (!wp_next_scheduled('baskerville_cleanup_cache')) {
			wp_schedule_event(time(), 'daily', 'baskerville_cleanup_cache');
		}

		// Cron for log file import to DB (every minute for faster blocking)
		if (!wp_next_scheduled('baskerville_process_log_files')) {
			wp_schedule_event(time(), 'baskerville_1min', 'baskerville_process_log_files');
		}

		// Cron for old log file cleanup (daily)
		if (!wp_next_scheduled('baskerville_cleanup_log_files')) {
			wp_schedule_event(time(), 'daily', 'baskerville_cleanup_log_files');
		}

		// Rebuild rewrite rules (in case there are custom endpoints/rewriting)
		flush_rewrite_rules();
	}

	/**
	 * Called upon plugin deactivation.
	 */
	public static function deactivate() {
		// Remove cron tasks
		wp_clear_scheduled_hook('baskerville_cleanup_stats');
		wp_clear_scheduled_hook('baskerville_cleanup_cache');
		wp_clear_scheduled_hook('baskerville_process_log_files');
		wp_clear_scheduled_hook('baskerville_cleanup_log_files');

		// Clean up rewrite rules
		flush_rewrite_rules();
	}
}
