<?php

if (!defined('ABSPATH')) {
	exit;
}

class Baskerville_Admin {

	private $stats;
	private $aiua;

	public function __construct($stats, $aiua) {
		$this->stats = $stats;
		$this->aiua = $aiua;

		add_action('admin_menu', array($this, 'add_admin_menu'));
		add_action('admin_enqueue_scripts', array($this, 'admin_menu_icon_style'));
		add_action('admin_init', array($this, 'register_settings'));
		add_action('admin_notices', array($this, 'show_activation_notices'));
		add_action('wp_ajax_baskerville_install_maxmind', array($this, 'ajax_install_maxmind'));
		add_action('wp_ajax_baskerville_update_deflect_geoip', array($this, 'ajax_update_deflect_geoip'));
		add_action('wp_ajax_baskerville_clear_geoip_cache', array($this, 'ajax_clear_geoip_cache'));
		add_action('wp_ajax_baskerville_run_benchmark', array($this, 'ajax_run_benchmark'));
		add_action('wp_ajax_baskerville_get_live_feed', array($this, 'ajax_get_live_feed'));
		add_action('wp_ajax_baskerville_get_live_stats', array($this, 'ajax_get_live_stats'));
		add_action('wp_ajax_baskerville_import_logs', array($this, 'ajax_import_logs'));
		add_action('wp_ajax_baskerville_ip_lookup', array($this, 'ajax_ip_lookup'));
		add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
	}

	public function enqueue_admin_scripts($hook) {
		// Only load on our plugin pages
		if (strpos($hook, 'baskerville') === false) {
			return;
		}

		// Enqueue Select2 (local files)
		wp_enqueue_style('select2', BASKERVILLE_PLUGIN_URL . 'assets/css/select2.min.css', array(), '4.1.0');
		wp_enqueue_script('select2', BASKERVILLE_PLUGIN_URL . 'assets/js/select2.min.js', array('jquery'), '4.1.0', false );

		// Enqueue Chart.js (local file)
		wp_enqueue_script('chartjs', BASKERVILLE_PLUGIN_URL . 'assets/js/chart.min.js', array(), '4.5.1', true);

		// Enqueue admin.js
		wp_enqueue_script('baskerville-admin', BASKERVILLE_PLUGIN_URL . 'assets/js/admin.js', array('jquery', 'select2', 'chartjs'), BASKERVILLE_VERSION, true);

		// Enqueue Live Feed JS only on the plugin settings page
		if ( $hook === 'toplevel_page_baskerville-settings' ) {
			wp_enqueue_script( 'baskerville-live-feed', BASKERVILLE_PLUGIN_URL . 'assets/js/live-feed.js', array( 'jquery', 'baskerville-admin' ), BASKERVILLE_VERSION, true );
		}

		// Pass nonces and i18n strings to admin.js
		wp_localize_script('baskerville-admin', 'baskervilleAdmin', array(
			'importLogsNonce'      => wp_create_nonce('baskerville_import_logs'),
			'installMaxmindNonce'  => wp_create_nonce('baskerville_install_maxmind'),
			'updateDeflectNonce'   => wp_create_nonce('baskerville_update_deflect_geoip'),
			'clearGeoipCacheNonce' => wp_create_nonce('baskerville_clear_geoip_cache'),
			'ipLookupNonce'        => wp_create_nonce('baskerville_ip_lookup'),
			'benchmarkNonce'       => wp_create_nonce('baskerville_benchmark'),
			'i18n' => array(
				// Import logs
				'importing'     => __( 'Importing...', 'baskerville-ai-security' ),
				'importFailed'  => __( 'Import failed', 'baskerville-ai-security' ),
				'importLogsNow' => __( 'Import Logs Now', 'baskerville-ai-security' ),
				'ajaxError'     => __( 'AJAX error occurred', 'baskerville-ai-security' ),
				// Select2
				'searchCompanies' => __( 'Search and select companies...', 'baskerville-ai-security' ),
				'searchCountries' => __( 'Search and select countries...', 'baskerville-ai-security' ),
				// Country charts
				'totalRequests'        => __( 'Total Requests', 'baskerville-ai-security' ),
				'trafficByCountryLast' => __( 'Traffic by Country — last', 'baskerville-ai-security' ),
				'requests'             => __( 'Requests', 'baskerville-ai-security' ),
				'banned403'            => __( '403 Blocked', 'baskerville-ai-security' ),
				'bansByCountryLast'    => __( '403 Bans by Country — last', 'baskerville-ai-security' ),
				'blockedRequests'      => __( 'Blocked Requests', 'baskerville-ai-security' ),
				// Live Feed
				'noRecentEvents'       => __( 'No recent events', 'baskerville-ai-security' ),
				'turnstileFailed'      => __( 'TURNSTILE FAILED', 'baskerville-ai-security' ),
				'challengeFailed'      => __( 'CHALLENGE FAILED', 'baskerville-ai-security' ),
				'banned'               => __( 'BANNED', 'baskerville-ai-security' ),
				'detected'             => __( 'DETECTED', 'baskerville-ai-security' ),
				'unknownBot'           => __( 'Unknown Bot', 'baskerville-ai-security' ),
				'turnstile'            => __( 'TURNSTILE', 'baskerville-ai-security' ),
				'ua'                   => __( 'UA:', 'baskerville-ai-security' ),
				'honeypot'             => __( 'HONEYPOT', 'baskerville-ai-security' ),
				'userAgent'            => __( 'USER-AGENT', 'baskerville-ai-security' ),
				'failedTurnstile'      => __( 'Failed Cloudflare Turnstile challenge', 'baskerville-ai-security' ),
				'noReason'             => __( 'No reason', 'baskerville-ai-security' ),
				'score'                => __( 'score', 'baskerville-ai-security' ),
				'banReason'            => __( 'Ban reason', 'baskerville-ai-security' ),
				'noData'               => __( 'No data', 'baskerville-ai-security' ),
				'attempts'             => __( 'attempts', 'baskerville-ai-security' ),
				// AI Bots chart
				'timeUtc'              => __( 'Time (UTC)', 'baskerville-ai-security' ),
				'hits'                 => __( 'Hits', 'baskerville-ai-security' ),
				'aiBotHitsLast'        => __( 'AI Bot Hits by Company - Last', 'baskerville-ai-security' ),
				// MaxMind installer
				'installing'           => __( 'Installing...', 'baskerville-ai-security' ),
				'downloadingLib'       => __( 'Downloading and installing library...', 'baskerville-ai-security' ),
				'retryInstall'         => __( 'Retry Installation', 'baskerville-ai-security' ),
				'installFailed'        => __( 'Installation failed. Please try again.', 'baskerville-ai-security' ),
				'installMaxmind'       => __( 'Install MaxMind Library', 'baskerville-ai-security' ),
				// Deflect GeoIP
				'downloading'          => __( 'Downloading...', 'baskerville-ai-security' ),
				'checkingUpdates'      => __( 'Checking for updates and downloading database...', 'baskerville-ai-security' ),
				'checkForUpdates'      => __( 'Check for Updates', 'baskerville-ai-security' ),
				'retry'                => __( 'Retry', 'baskerville-ai-security' ),
				'requestFailed'        => __( 'Request failed. Please try again.', 'baskerville-ai-security' ),
				// GeoIP cache
				'clearing'             => __( 'Clearing...', 'baskerville-ai-security' ),
				'clearingCache'        => __( 'Clearing cache...', 'baskerville-ai-security' ),
				'clearGeoipCache'      => __( 'Clear GeoIP Cache', 'baskerville-ai-security' ),
				'clearCacheFailed'     => __( 'Failed to clear cache. Please try again.', 'baskerville-ai-security' ),
				// Turnstile test
				'turnstileWorking'     => __( 'Turnstile widget is working!', 'baskerville-ai-security' ),
				'tokenReceived'        => __( 'Token received (first 20 chars):', 'baskerville-ai-security' ),
				'turnstileError'       => __( 'Turnstile error:', 'baskerville-ai-security' ),
				// Analytics charts
				'humans'               => __( 'Humans', 'baskerville-ai-security' ),
				'automated'            => __( 'Automated', 'baskerville-ai-security' ),
				'time'                 => __( 'Time', 'baskerville-ai-security' ),
				'visits'               => __( 'Visits', 'baskerville-ai-security' ),
				'humansVsAutoLast'     => __( 'Humans vs Automated — last', 'baskerville-ai-security' ),
				'total'                => __( 'Total:', 'baskerville-ai-security' ),
				'humansLabel'          => __( 'Humans:', 'baskerville-ai-security' ),
				'automatedLabel'       => __( 'Automated:', 'baskerville-ai-security' ),
				'trafficDistLast'      => __( 'Traffic Distribution — last', 'baskerville-ai-security' ),
				'badBots'              => __( 'Bad Bots', 'baskerville-ai-security' ),
				'aiBots'               => __( 'AI Bots', 'baskerville-ai-security' ),
				'otherBots'            => __( 'Other Bots', 'baskerville-ai-security' ),
				'verifiedCrawlers'     => __( 'Verified Crawlers', 'baskerville-ai-security' ),
				'count'                => __( 'Count', 'baskerville-ai-security' ),
				'botTypesLast'         => __( 'Bot Types — last', 'baskerville-ai-security' ),
				'totalBots'            => __( 'Total bots:', 'baskerville-ai-security' ),
				'botTypesDistLast'     => __( 'Bot Types Distribution — last', 'baskerville-ai-security' ),
				'passedHumans'         => __( 'Passed (Humans)', 'baskerville-ai-security' ),
				'failedBots'           => __( 'Failed (Bots)', 'baskerville-ai-security' ),
				'challenges'           => __( 'Challenges', 'baskerville-ai-security' ),
				'turnstileChallenges'  => __( 'Turnstile Challenges', 'baskerville-ai-security' ),
				'redirects'            => __( 'Redirects:', 'baskerville-ai-security' ),
				'precision'            => __( 'Precision:', 'baskerville-ai-security' ),
				'challenged'           => __( 'Challenged:', 'baskerville-ai-security' ),
				'passed'               => __( 'Passed:', 'baskerville-ai-security' ),
				'failed'               => __( 'Failed:', 'baskerville-ai-security' ),
				'noTurnstileData'      => __( 'No Turnstile data available. Enable Turnstile challenge for borderline scores to see data here.', 'baskerville-ai-security' ),
				'noChallengesRecorded' => __( 'No challenges recorded', 'baskerville-ai-security' ),
				'noDataPeriod'         => __( 'No data available for the selected period', 'baskerville-ai-security' ),
				'noDataAvailable'      => __( 'No data available', 'baskerville-ai-security' ),
				// IP Lookup
				'enterIpAddress'       => __( 'Please enter an IP address', 'baskerville-ai-security' ),
				'searching'            => __( 'Searching...', 'baskerville-ai-security' ),
				'loading'              => __( 'Loading...', 'baskerville-ai-security' ),
				'search'               => __( 'Search', 'baskerville-ai-security' ),
				'ipLabel'              => __( 'IP:', 'baskerville-ai-security' ),
				'statusLabel'          => __( 'Status:', 'baskerville-ai-security' ),
				'currentlyBanned'      => __( 'Currently BANNED', 'baskerville-ai-security' ),
				'notBanned'            => __( 'Not currently banned', 'baskerville-ai-security' ),
				'countryLabel'         => __( 'Country:', 'baskerville-ai-security' ),
				'totalEvents'          => __( 'Total events:', 'baskerville-ai-security' ),
				'blockEvents'          => __( 'Block events:', 'baskerville-ai-security' ),
				'recentEvents'         => __( 'Recent Events (last 100)', 'baskerville-ai-security' ),
				'timeHeader'           => __( 'Time', 'baskerville-ai-security' ),
				'classification'       => __( 'Classification', 'baskerville-ai-security' ),
				'scoreHeader'          => __( 'Score', 'baskerville-ai-security' ),
				'blockReasonHeader'    => __( 'Block Reason', 'baskerville-ai-security' ),
				'userAgentHeader'      => __( 'User Agent', 'baskerville-ai-security' ),
				'noEventsFound'        => __( 'No events found for this IP address.', 'baskerville-ai-security' ),
				'errorSearchingIp'     => __( 'Error searching for IP', 'baskerville-ai-security' ),
				// Benchmark
				'running'              => __( 'Running...', 'baskerville-ai-security' ),
				'benchmarkError'       => __( 'Error', 'baskerville-ai-security' ),
				'benchmarkAjaxError'   => __( 'AJAX error', 'baskerville-ai-security' ),
			),
		));
	}

	/**
	 * Enqueue custom CSS for menu icon size
	 */
	public function admin_menu_icon_style() {
		wp_add_inline_style( 'wp-admin', '#adminmenu .toplevel_page_baskerville-settings div.wp-menu-image.svg { background-size: 24px auto; }' );
	}

	/**
	 * Show activation notices (e.g., Deflect GeoIP download result)
	 */
	public function show_activation_notices() {
		// Check for Deflect GeoIP activation result
		$result = get_transient('baskerville_deflect_geoip_activation_result');
		if ($result) {
			delete_transient('baskerville_deflect_geoip_activation_result');

			$class = $result['success'] ? 'notice-success' : 'notice-error';
			$message = $result['message'] ?? __('Unknown result', 'baskerville-ai-security');

			printf(
				'<div class="notice %s is-dismissible"><p><strong>' . esc_html__( 'Baskerville:', 'baskerville-ai-security' ) . '</strong> %s</p></div>',
				esc_attr($class),
				esc_html($message)
			);
		}
	}

	public function add_admin_menu() {
		// Main menu page (Live Feed is the default)
		// Load custom SVG icon
		$icon_file = BASKERVILLE_PLUGIN_PATH . 'assets/icon-menu.svg';
		$icon = 'dashicons-shield'; // fallback
		if (file_exists($icon_file)) {
			// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Local file read for menu icon
			$icon = 'data:image/svg+xml;base64,' . base64_encode(file_get_contents($icon_file));
		}

		add_menu_page(
			esc_html__('Baskerville', 'baskerville-ai-security'),
			esc_html__('Baskerville', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-settings',
			array($this, 'admin_page'),
			$icon,
			80
		);

		// Submenu pages for each tab
		add_submenu_page(
			'baskerville-settings',
			esc_html__('Live Feed', 'baskerville-ai-security'),
			esc_html__('Live Feed', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-settings',
			array($this, 'admin_page')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Bot Control', 'baskerville-ai-security'),
			esc_html__('Bot Control', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-bot-protection',
			array($this, 'admin_page_bot_protection')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('AI Bot Control', 'baskerville-ai-security'),
			esc_html__('AI Bot Control', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-ai-bot-control',
			array($this, 'admin_page_ai_bot_control')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Country Control', 'baskerville-ai-security'),
			esc_html__('Country Control', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-country-control',
			array($this, 'admin_page_country_control')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Burst Protection', 'baskerville-ai-security'),
			esc_html__('Burst Protection', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-burst-protection',
			array($this, 'admin_page_burst_protection')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Rate Limits', 'baskerville-ai-security'),
			esc_html__('Rate Limits', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-rate-limits',
			array($this, 'admin_page_rate_limits')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Turnstile', 'baskerville-ai-security'),
			esc_html__('Turnstile', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-turnstile',
			array($this, 'admin_page_turnstile')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Analytics', 'baskerville-ai-security'),
			esc_html__('Analytics', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-analytics',
			array($this, 'admin_page_analytics')
		);

		add_submenu_page(
			'baskerville-settings',
			esc_html__('Settings', 'baskerville-ai-security'),
			esc_html__('Settings', 'baskerville-ai-security'),
			'manage_options',
			'baskerville-settings-tab',
			array($this, 'admin_page_settings')
		);
	}

	// Callback methods for submenu pages - set tab and call main admin_page
	public function admin_page_bot_protection() {
		$_GET['tab'] = 'bot-protection';
		$this->admin_page();
	}

	public function admin_page_ai_bot_control() {
		$_GET['tab'] = 'ai-bot-control';
		$this->admin_page();
	}

	public function admin_page_country_control() {
		$_GET['tab'] = 'country-control';
		$this->admin_page();
	}

	public function admin_page_burst_protection() {
		$_GET['tab'] = 'burst-protection';
		$this->admin_page();
	}

	public function admin_page_rate_limits() {
		$_GET['tab'] = 'rate-limits';
		$this->admin_page();
	}

	public function admin_page_turnstile() {
		$_GET['tab'] = 'turnstile';
		$this->admin_page();
	}

	public function admin_page_analytics() {
		$_GET['tab'] = 'analytics';
		$this->admin_page();
	}

	public function admin_page_settings() {
		$_GET['tab'] = 'settings';
		$this->admin_page();
	}

	public function register_settings() {
		// Register settings
		register_setting(
			'baskerville_settings_group',
			'baskerville_settings',
			array($this, 'sanitize_settings')
		);

		// Register burst protection threshold options separately
		register_setting(
			'baskerville_settings_group',
			'baskerville_nocookie_threshold',
			array(
				'type' => 'integer',
				'sanitize_callback' => function($value) {
					return max(1, min(1000, (int) $value));
				},
				'default' => 10
			)
		);
		register_setting(
			'baskerville_settings_group',
			'baskerville_nocookie_window_sec',
			array(
				'type' => 'integer',
				'sanitize_callback' => function($value) {
					return max(10, min(3600, (int) $value));
				},
				'default' => 60
			)
		);
		register_setting(
			'baskerville_settings_group',
			'baskerville_nojs_threshold',
			array(
				'type' => 'integer',
				'sanitize_callback' => function($value) {
					return max(1, min(1000, (int) $value));
				},
				'default' => 20
			)
		);
		register_setting(
			'baskerville_settings_group',
			'baskerville_nojs_window_sec',
			array(
				'type' => 'integer',
				'sanitize_callback' => function($value) {
					return max(10, min(3600, (int) $value));
				},
				'default' => 60
			)
		);
		register_setting(
			'baskerville_settings_group',
			'baskerville_ban_ttl_sec',
			array(
				'type' => 'integer',
				'sanitize_callback' => function($value) {
					return max(60, min(86400, (int) $value));
				},
				'default' => 600
			)
		);

		// ===== Bot Control Tab =====
		add_settings_section(
			'baskerville_bot_protection_section',
			'',
			null,
			'baskerville-bot-protection'
		);

		add_settings_field(
			'bot_protection_enabled',
			'',
			array($this, 'render_bot_protection_enabled_field'),
			'baskerville-bot-protection',
			'baskerville_bot_protection_section'
		);

		// ===== Burst Protection Tab =====
		add_settings_section(
			'baskerville_burst_protection_section',
			'',
			null,
			'baskerville-burst-protection'
		);

		// Note: burst_protection_enabled is now rendered manually at the top of the Burst Protection tab
		// The content (thresholds, etc.) is rendered via render_burst_protection_content()

		// ===== Rate Limits Tab =====
		add_settings_section(
			'baskerville_rate_limits_section',
			'',
			null,
			'baskerville-rate-limits'
		);

		// Note: api_rate_limit_enabled is now rendered manually at the top of the Rate Limits tab
		// add_settings_field(
		// 	'api_rate_limit_enabled',
		// 	esc_html__('Enable API Rate Limiting', 'baskerville-ai-security'),
		// 	array($this, 'render_api_rate_limit_enabled_field'),
		// 	'baskerville-rate-limits',
		// 	'baskerville_rate_limits_section'
		// );

		// ===== Settings Tab =====
		add_settings_section(
			'baskerville_settings_section',
			esc_html__('General Settings', 'baskerville-ai-security'),
			null,
			'baskerville-settings'
		);

		// Ban duration field
		add_settings_field(
			'ban_ttl_sec',
			esc_html__('Ban Duration', 'baskerville-ai-security'),
			array($this, 'render_ban_duration_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// Log page visits field
		add_settings_field(
			'log_page_visits',
			esc_html__('Logging Mode', 'baskerville-ai-security'),
			array($this, 'render_log_page_visits_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// Data retention field
		add_settings_field(
			'retention_days',
			esc_html__('Data Retention', 'baskerville-ai-security'),
			array($this, 'render_retention_days_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// IP Whitelist field
		add_settings_field(
			'ip_whitelist',
			esc_html__('Allowed IPs', 'baskerville-ai-security'),
			array($this, 'render_ip_whitelist_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// ===== Country Control Tab =====
		add_settings_section(
			'baskerville_country_control_section',
			esc_html__('Country Control Settings', 'baskerville-ai-security'),
			null,
			'baskerville-country-control'
		);

		// Note: geoip_enabled is now rendered manually at the top of the Country Control tab
		// add_settings_field(
		// 	'geoip_enabled',
		// 	esc_html__('Enable Country Control', 'baskerville-ai-security'),
		// 	array($this, 'render_geoip_enabled_field'),
		// 	'baskerville-country-control',
		// 	'baskerville_country_control_section'
		// );

		add_settings_field(
			'geoip_mode',
			esc_html__('GeoIP Access Mode', 'baskerville-ai-security'),
			array($this, 'render_geoip_mode_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		add_settings_field(
			'blacklist_countries',
			esc_html__('Block List Countries', 'baskerville-ai-security'),
			array($this, 'render_blacklist_countries_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		add_settings_field(
			'whitelist_countries',
			esc_html__('Allow List Countries', 'baskerville-ai-security'),
			array($this, 'render_whitelist_countries_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		// ===== AI Bot Control Tab =====
		add_settings_section(
			'baskerville_ai_bot_control_section',
			esc_html__('AI Bot Access Control', 'baskerville-ai-security'),
			array($this, 'render_ai_bot_control_section'),
			'baskerville-ai-bot-control'
		);

		// ai_bot_control_enabled - now rendered manually at top of form

		add_settings_field(
			'ai_bot_blocking_mode',
			esc_html__('AI Bot Access Mode', 'baskerville-ai-security'),
			array($this, 'render_ai_bot_mode_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'blacklist_ai_companies',
			esc_html__('Block List Companies', 'baskerville-ai-security'),
			array($this, 'render_blacklist_ai_companies_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'whitelist_ai_companies',
			esc_html__('Allow List Companies', 'baskerville-ai-security'),
			array($this, 'render_whitelist_ai_companies_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		// Honeypot fields (moved from general settings)
		add_settings_field(
			'honeypot_enabled',
			esc_html__('Honeypot Trap', 'baskerville-ai-security'),
			array($this, 'render_honeypot_enabled_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'honeypot_ban',
			esc_html__('Ban on Honeypot Trigger', 'baskerville-ai-security'),
			array($this, 'render_honeypot_ban_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);
	}

	public function sanitize_settings($input) {
		// Get existing settings to preserve values not in current form submission
		$existing = get_option('baskerville_settings', array());
		$sanitized = array();

		// Master protection switch
		$sanitized['master_protection_enabled'] = isset($input['master_protection_enabled']) ? (bool) $input['master_protection_enabled'] : false;

		// Tab enable/disable switches - preserve existing values if not in input
		$sanitized['bot_protection_enabled'] = isset($input['bot_protection_enabled'])
			? (bool) $input['bot_protection_enabled']
			: (isset($existing['bot_protection_enabled']) ? $existing['bot_protection_enabled'] : true);
		$sanitized['burst_protection_enabled'] = isset($input['burst_protection_enabled'])
			? (bool) $input['burst_protection_enabled']
			: (isset($existing['burst_protection_enabled']) ? $existing['burst_protection_enabled'] : true);
		$sanitized['api_rate_limit_enabled'] = isset($input['api_rate_limit_enabled'])
			? (bool) $input['api_rate_limit_enabled']
			: (isset($existing['api_rate_limit_enabled']) ? $existing['api_rate_limit_enabled'] : true);
		$sanitized['geoip_enabled'] = isset($input['geoip_enabled'])
			? (bool) $input['geoip_enabled']
			: (isset($existing['geoip_enabled']) ? $existing['geoip_enabled'] : false);
		$sanitized['ai_bot_control_enabled'] = isset($input['ai_bot_control_enabled'])
			? (bool) $input['ai_bot_control_enabled']
			: (isset($existing['ai_bot_control_enabled']) ? $existing['ai_bot_control_enabled'] : true);

		$sanitized['ban_all_detected_bots'] = isset($input['ban_all_detected_bots'])
			? (bool) $input['ban_all_detected_bots']
			: (isset($existing['ban_all_detected_bots']) ? $existing['ban_all_detected_bots'] : false);

		if (isset($input['instant_ban_threshold'])) {
			$threshold = (int) $input['instant_ban_threshold'];
			$sanitized['instant_ban_threshold'] = max(0, min(100, $threshold)); // Clamp between 0-100
		} elseif (isset($existing['instant_ban_threshold'])) {
			$sanitized['instant_ban_threshold'] = $existing['instant_ban_threshold'];
		}

		// Bot Control settings - preserve existing if not in input
		$sanitized['allow_verified_crawlers'] = isset($input['allow_verified_crawlers'])
			? (bool) $input['allow_verified_crawlers']
			: (isset($existing['allow_verified_crawlers']) ? $existing['allow_verified_crawlers'] : true);

		// Legacy checkboxes - preserve existing if not in input
		$sanitized['ban_bots_403'] = isset($input['ban_bots_403'])
			? (bool) $input['ban_bots_403']
			: (isset($existing['ban_bots_403']) ? $existing['ban_bots_403'] : false);

		if (isset($input['log_mode'])) {
			$mode = sanitize_text_field($input['log_mode']);
			$sanitized['log_mode'] = in_array($mode, array('disabled', 'file', 'database')) ? $mode : 'database';
		}

		if (isset($input['geoip_mode'])) {
			// Allow 'blacklist', 'whitelist', or 'allow_all'
			$mode = sanitize_text_field($input['geoip_mode']);
			$sanitized['geoip_mode'] = in_array($mode, array('blacklist', 'whitelist', 'allow_all')) ? $mode : 'allow_all';
		}

		if (isset($input['blacklist_countries'])) {
			// Sanitize country codes: comes as array from select2, convert to comma-separated
			if (is_array($input['blacklist_countries'])) {
				$countries = array_map('strtoupper', array_map('sanitize_text_field', $input['blacklist_countries']));
				$sanitized['blacklist_countries'] = implode(',', $countries);
			} else {
				// Fallback for manual input (backwards compatibility)
				$countries = sanitize_text_field($input['blacklist_countries']);
				$countries = strtoupper(trim($countries));
				$sanitized['blacklist_countries'] = $countries;
			}
		}

		if (isset($input['whitelist_countries'])) {
			// Sanitize country codes: comes as array from select2, convert to comma-separated
			if (is_array($input['whitelist_countries'])) {
				$countries = array_map('strtoupper', array_map('sanitize_text_field', $input['whitelist_countries']));
				$sanitized['whitelist_countries'] = implode(',', $countries);
			} else {
				// Fallback for manual input (backwards compatibility)
				$countries = sanitize_text_field($input['whitelist_countries']);
				$countries = strtoupper(trim($countries));
				$sanitized['whitelist_countries'] = $countries;
			}
		}

		// Keep old 'banned_countries' for backwards compatibility, but deprecate it
		if (isset($input['banned_countries'])) {
			$countries = sanitize_text_field($input['banned_countries']);
			$countries = strtoupper(trim($countries));
			$sanitized['banned_countries'] = $countries;
		}

		// AI Bot blocking mode
		if (isset($input['ai_bot_blocking_mode'])) {
			$mode = sanitize_text_field($input['ai_bot_blocking_mode']);
			$sanitized['ai_bot_blocking_mode'] = in_array($mode, array('blacklist', 'whitelist', 'allow_all', 'block_all')) ? $mode : 'allow_all';
		}

		// Blacklist AI companies
		if (isset($input['blacklist_ai_companies'])) {
			if (is_array($input['blacklist_ai_companies'])) {
				$companies = array_map('sanitize_text_field', $input['blacklist_ai_companies']);
				$sanitized['blacklist_ai_companies'] = implode(',', $companies);
			} else {
				$companies = sanitize_text_field($input['blacklist_ai_companies']);
				$sanitized['blacklist_ai_companies'] = trim($companies);
			}
		}

		// Whitelist AI companies
		if (isset($input['whitelist_ai_companies'])) {
			if (is_array($input['whitelist_ai_companies'])) {
				$companies = array_map('sanitize_text_field', $input['whitelist_ai_companies']);
				$sanitized['whitelist_ai_companies'] = implode(',', $companies);
			} else {
				$companies = sanitize_text_field($input['whitelist_ai_companies']);
				$sanitized['whitelist_ai_companies'] = trim($companies);
			}
		}

		// Honeypot settings - if AI bot control tab submitted, unchecked = false; otherwise preserve existing
		$is_ai_tab = isset($input['ai_bot_control_tab']);
		$sanitized['honeypot_enabled'] = isset($input['honeypot_enabled'])
			? (bool) $input['honeypot_enabled']
			: ($is_ai_tab ? false : (isset($existing['honeypot_enabled']) ? $existing['honeypot_enabled'] : false));
		$sanitized['honeypot_ban'] = isset($input['honeypot_ban'])
			? (bool) $input['honeypot_ban']
			: ($is_ai_tab ? false : (isset($existing['honeypot_ban']) ? $existing['honeypot_ban'] : false));

		// Burst protection enabled - preserve existing if not in input
		$sanitized['enable_burst_protection'] = isset($input['enable_burst_protection'])
			? (bool) $input['enable_burst_protection']
			: (isset($existing['enable_burst_protection']) ? $existing['enable_burst_protection'] : false);

		// Note: api_rate_limit_enabled is already handled above in tab switches
		if (isset($input['api_rate_limit_requests'])) {
			$sanitized['api_rate_limit_requests'] = max(1, min(10000, (int) $input['api_rate_limit_requests']));
		}
		if (isset($input['api_rate_limit_window'])) {
			$sanitized['api_rate_limit_window'] = max(10, min(3600, (int) $input['api_rate_limit_window']));
		}

		// Turnstile settings
		$sanitized['turnstile_enabled'] = isset($input['turnstile_enabled'])
			? (bool) $input['turnstile_enabled']
			: (isset($existing['turnstile_enabled']) ? $existing['turnstile_enabled'] : false);

		if (isset($input['turnstile_site_key'])) {
			$sanitized['turnstile_site_key'] = sanitize_text_field($input['turnstile_site_key']);
		} else {
			$sanitized['turnstile_site_key'] = isset($existing['turnstile_site_key']) ? $existing['turnstile_site_key'] : '';
		}

		if (isset($input['turnstile_secret_key'])) {
			$sanitized['turnstile_secret_key'] = sanitize_text_field($input['turnstile_secret_key']);
		} else {
			$sanitized['turnstile_secret_key'] = isset($existing['turnstile_secret_key']) ? $existing['turnstile_secret_key'] : '';
		}

		// Turnstile borderline challenge settings
		$sanitized['turnstile_challenge_borderline'] = isset($input['turnstile_challenge_borderline'])
			? (bool) $input['turnstile_challenge_borderline']
			: (isset($existing['turnstile_challenge_borderline']) ? $existing['turnstile_challenge_borderline'] : false);

		$sanitized['turnstile_under_attack'] = isset($input['turnstile_under_attack'])
			? (bool) $input['turnstile_under_attack']
			: (isset($existing['turnstile_under_attack']) ? $existing['turnstile_under_attack'] : false);

		if (isset($input['turnstile_borderline_min'])) {
			$sanitized['turnstile_borderline_min'] = max(0, min(100, (int) $input['turnstile_borderline_min']));
		} else {
			$sanitized['turnstile_borderline_min'] = isset($existing['turnstile_borderline_min']) ? $existing['turnstile_borderline_min'] : 40;
		}

		if (isset($input['turnstile_borderline_max'])) {
			$sanitized['turnstile_borderline_max'] = max(0, min(100, (int) $input['turnstile_borderline_max']));
		} else {
			$sanitized['turnstile_borderline_max'] = isset($existing['turnstile_borderline_max']) ? $existing['turnstile_borderline_max'] : 70;
		}

		// Flush rewrite rules when settings are saved (for honeypot route)
		flush_rewrite_rules();

		// Merge with existing settings to preserve values not in current form
		return array_merge($existing, $sanitized);
	}

	public function render_ban_bots_403_field() {
		$options = get_option('baskerville_settings', array());
		// Default to true if not set
		$checked = !isset($options['ban_bots_403']) || $options['ban_bots_403'];
		?>
		<label>
			<input type="checkbox" name="baskerville_settings[ban_bots_403]" value="1" <?php checked($checked, true); ?> />
			<?php esc_html_e('Enable 403 ban for detected bots', 'baskerville-ai-security'); ?>
		</label>
		<?php
	}

	public function render_log_page_visits_field() {
		$options = get_option('baskerville_settings', array());
		// Default to 'database' for immediate blocking and analytics
		$mode = isset($options['log_mode']) ? $options['log_mode'] : 'database';
		?>
		<fieldset>
			<legend class="screen-reader-text"><span><?php esc_html_e('Page Visit Logging Mode', 'baskerville-ai-security'); ?></span></legend>

			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[log_mode]"
					   value="disabled"
					   <?php checked($mode, 'disabled'); ?> />
				<strong><?php esc_html_e('Disabled', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('No page visit logging (blocks & fingerprints still logged)', 'baskerville-ai-security'); ?>
				<span class="baskerville-text-success"><?php esc_html_e( '⚡ ~0ms overhead', 'baskerville-ai-security' ); ?></span>
			</label>

			<label class="baskerville-label-block">
				<input type="radio" name="baskerville_settings[log_mode]" value="file" <?php checked($mode, 'file'); ?> />
				<strong><?php esc_html_e('File Logging', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Write to log file, batch import to DB every minute', 'baskerville-ai-security'); ?>
				<span class="baskerville-text-success"><?php esc_html_e('⚡ ~1-2ms overhead', 'baskerville-ai-security'); ?></span>
				<strong class="baskerville-text-info"><?php esc_html_e('✓ Recommended', 'baskerville-ai-security'); ?></strong>
			</label>

			<label class="baskerville-label-block">
				<input type="radio" name="baskerville_settings[log_mode]" value="database" <?php checked($mode, 'database'); ?> />
				<strong><?php esc_html_e('Direct Database', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Write to database immediately (high overhead)', 'baskerville-ai-security'); ?>
				<span class="baskerville-text-warning"><?php esc_html_e('⚠️ ~500ms overhead on shared hosting', 'baskerville-ai-security'); ?></span>
			</label>

			<p class="description baskerville-alert baskerville-alert-neutral baskerville-alert-xs baskerville-alert-mt">
				<strong><?php esc_html_e('💡 Recommendation:', 'baskerville-ai-security'); ?></strong><br>
				<?php
				printf(
					/* translators: %1$s: opening strong tag, %2$s: closing strong tag */
					esc_html__( 'Use %1$sFile Logging%2$s for best performance on shared hosting (GoDaddy, Bluehost, etc.)', 'baskerville-ai-security' ),
					'<strong>',
					'</strong>'
				);
				?><br>
				<?php esc_html_e('Full analytics with minimal overhead. Logs are processed in background every minute.', 'baskerville-ai-security'); ?>
			</p>
		</fieldset>
		<?php
	}

	public function render_geoip_mode_field() {
		$options = get_option('baskerville_settings', array());
		// Default to allow_all if not set
		$mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';
		?>
		<fieldset>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[geoip_mode]"
					   value="allow_all"
					   class="baskerville-geoip-mode-radio"
					   <?php checked($mode, 'allow_all'); ?> />
				<strong><?php esc_html_e('Allow All Countries', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('No GeoIP restrictions (allow all countries)', 'baskerville-ai-security'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[geoip_mode]"
					   value="blacklist"
					   class="baskerville-geoip-mode-radio"
					   <?php checked($mode, 'blacklist'); ?> />
				<strong><?php esc_html_e('Block List', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Block access from specified countries', 'baskerville-ai-security'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[geoip_mode]"
					   value="whitelist"
					   class="baskerville-geoip-mode-radio"
					   <?php checked($mode, 'whitelist'); ?> />
				<strong><?php esc_html_e('Allow List', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Allow access ONLY from specified countries', 'baskerville-ai-security'); ?>
			</label>
		</fieldset>
		<p class="description">
			<?php esc_html_e('Choose whether to allow all countries, block specific countries, or allow only specific countries.', 'baskerville-ai-security'); ?>
		</p>

		<?php
	}

	public function render_blacklist_countries_field() {
		$options = get_option('baskerville_settings', array());
		$blacklist_countries = isset($options['blacklist_countries']) ? $options['blacklist_countries'] : '';

		// Parse selected countries from comma-separated string
		$selected_countries = array();
		if (!empty($blacklist_countries)) {
			$selected_countries = array_map('trim', array_map('strtoupper', explode(',', $blacklist_countries)));
		}

		// Get full countries list
		$countries = $this->get_countries_list();

		// Check which GeoIP source is available
		$geoip_source = $this->get_geoip_source_name();
		?>
		<div>
			<select name="baskerville_settings[blacklist_countries][]"
					id="baskerville_blacklist_countries"
					class="baskerville-country-select baskerville-input-full"
					multiple="multiple">
				<?php foreach ($countries as $code => $name): ?>
					<option value="<?php echo esc_attr($code); ?>"
							<?php echo in_array($code, $selected_countries) ? 'selected' : ''; ?>>
						<?php echo esc_html($name . ' (' . $code . ')'); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<p class="description">
				<strong class="baskerville-text-danger"><?php esc_html_e('Block access from these countries', 'baskerville-ai-security'); ?></strong><br>
				<?php esc_html_e('Search and select countries to block. You can select multiple countries.', 'baskerville-ai-security'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Block List" mode is selected above.', 'baskerville-ai-security'); ?></em><br>
				<strong><?php esc_html_e('Current GeoIP source:', 'baskerville-ai-security'); ?></strong> <?php echo esc_html($geoip_source); ?>
				<?php if ($geoip_source === 'MaxMind (if configured)'): ?>
					<br><em><?php esc_html_e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville-ai-security'); ?></em>
					<br><em><?php esc_html_e('Download from: ', 'baskerville-ai-security'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank"><?php esc_html_e( 'MaxMind GeoLite2', 'baskerville-ai-security'); ?></a></em>
				<?php endif; ?>
			</p>
		</div>
		<?php
	}

	public function render_whitelist_countries_field() {
		$options = get_option('baskerville_settings', array());
		$whitelist_countries = isset($options['whitelist_countries']) ? $options['whitelist_countries'] : '';

		// Parse selected countries from comma-separated string
		$selected_countries = array();
		if (!empty($whitelist_countries)) {
			$selected_countries = array_map('trim', array_map('strtoupper', explode(',', $whitelist_countries)));
		}

		// Get full countries list
		$countries = $this->get_countries_list();

		// Check which GeoIP source is available
		$geoip_source = $this->get_geoip_source_name();
		?>
		<div>
			<select name="baskerville_settings[whitelist_countries][]"
					id="baskerville_whitelist_countries"
					class="baskerville-country-select baskerville-input-full"
					multiple="multiple">
				<?php foreach ($countries as $code => $name): ?>
					<option value="<?php echo esc_attr($code); ?>"
							<?php echo in_array($code, $selected_countries) ? 'selected' : ''; ?>>
						<?php echo esc_html($name . ' (' . $code . ')'); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<p class="description">
				<strong class="baskerville-text-primary"><?php esc_html_e('Allow access ONLY from these countries', 'baskerville-ai-security'); ?></strong><br>
				<?php esc_html_e('Search and select countries to allow. You can select multiple countries.', 'baskerville-ai-security'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Allow List" mode is selected above.', 'baskerville-ai-security'); ?></em><br>
				<strong><?php esc_html_e('Current GeoIP source:', 'baskerville-ai-security'); ?></strong> <?php echo esc_html($geoip_source); ?>
				<?php if ($geoip_source === 'MaxMind (if configured)'): ?>
					<br><em><?php esc_html_e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville-ai-security'); ?></em>
					<br><em><?php esc_html_e('Download from: ', 'baskerville-ai-security'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank"><?php esc_html_e('MaxMind GeoLite2', 'baskerville-ai-security'); ?></a></em>
				<?php endif; ?>
			</p>
		</div>
		<?php
	}

	/* ===== New Enable/Disable Field Renderers ===== */

	public function render_bot_protection_enabled_field() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['bot_protection_enabled']) ? $options['bot_protection_enabled'] : true;
		?>
		<div class="baskerville-toggle-label">
			<span class="baskerville-toggle-text">
				<?php esc_html_e('Bot Control', 'baskerville-ai-security'); ?>
			</span>
			<input type="hidden" name="baskerville_settings[bot_protection_enabled]" value="0">
			<label class="baskerville-toggle-switch">
				<input type="checkbox" name="baskerville_settings[bot_protection_enabled]" value="1" <?php checked($enabled, true); ?> />
				<span class="baskerville-toggle-slider-regular"></span>
			</label>
			<span class="baskerville-toggle-text">
				<?php echo $enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
			</span>
		</div>
		<?php
	}

	public function render_burst_protection_enabled_field() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['burst_protection_enabled']) ? $options['burst_protection_enabled'] : true;
		?>
		<div class="baskerville-toggle-label">
			<span class="baskerville-toggle-text">
				<?php esc_html_e('Burst Protection', 'baskerville-ai-security'); ?>
			</span>
			<input type="hidden" name="baskerville_settings[burst_protection_enabled]" value="0">
			<label class="baskerville-toggle-switch">
				<input type="checkbox" name="baskerville_settings[burst_protection_enabled]" value="1" <?php checked($enabled, true); ?> />
				<span class="baskerville-toggle-slider-regular"></span>
			</label>
			<span class="baskerville-toggle-text">
				<?php echo $enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
			</span>
		</div>
		<?php
	}

	public function render_api_rate_limit_enabled_field() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;
		?>
		<label>
			<input type="hidden" name="baskerville_settings[api_rate_limit_enabled]" value="0">
			<input type="checkbox" name="baskerville_settings[api_rate_limit_enabled]" value="1" <?php checked($enabled, true); ?> />
			<?php esc_html_e('Enable API rate limiting', 'baskerville-ai-security'); ?>
		</label>
		<?php
	}

	public function render_geoip_enabled_field() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['geoip_enabled']) ? $options['geoip_enabled'] : false;
		?>
		<label>
			<input type="hidden" name="baskerville_settings[geoip_enabled]" value="0">
			<input type="checkbox" name="baskerville_settings[geoip_enabled]" value="1" <?php checked($enabled, true); ?> />
			<?php esc_html_e('Enable country-based access control', 'baskerville-ai-security'); ?>
		</label>
		<?php
	}

	public function render_ai_bot_control_enabled_field() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['ai_bot_control_enabled']) ? $options['ai_bot_control_enabled'] : true;
		?>
		<label>
			<input type="hidden" name="baskerville_settings[ai_bot_control_enabled]" value="0">
			<input type="checkbox" name="baskerville_settings[ai_bot_control_enabled]" value="1" <?php checked($enabled, true); ?> />
			<?php esc_html_e('Enable AI bot crawler control', 'baskerville-ai-security'); ?>
		</label>
		<?php
	}

	public function render_ban_duration_field() {
		$ban_ttl = (int) get_option('baskerville_ban_ttl_sec', 600);
		?>
		<input type="number" name="baskerville_ban_ttl_sec" value="<?php echo esc_attr($ban_ttl); ?>" min="1" max="86400" class="baskerville-input-md">
		<span><?php esc_html_e('seconds', 'baskerville-ai-security'); ?></span>
		<p class="description">
			<?php esc_html_e('How long IP addresses are banned after triggering protection (1-86400 seconds)', 'baskerville-ai-security'); ?>
		</p>
		<?php
	}

	public function render_retention_days_field() {
		$retention = $this->stats->get_retention_days();
		?>
		<input type="number" name="baskerville_retention_days" value="<?php echo esc_attr($retention); ?>" min="1" max="365" class="baskerville-input-md">
		<span><?php esc_html_e('days', 'baskerville-ai-security'); ?></span>
		<p class="description">
			<?php esc_html_e('Statistics older than this will be automatically deleted (1-365 days)', 'baskerville-ai-security'); ?>
		</p>
		<?php
	}

	public function render_ip_whitelist_field() {
		$whitelist = get_option('baskerville_ip_whitelist', '');
		?>
		<textarea name="baskerville_ip_whitelist" rows="5" cols="50" class="large-text code"><?php echo esc_textarea($whitelist); ?></textarea>
		<p class="description">
			<?php esc_html_e('IP addresses that bypass all checks (one per line or comma-separated)', 'baskerville-ai-security'); ?>
		</p>
		<?php
	}

	public function render_ai_bot_control_section() {
		?>
		<p><?php esc_html_e('Control access from AI bot crawlers based on their company ownership.', 'baskerville-ai-security'); ?></p>
		<?php
	}

	public function render_ai_bot_mode_field() {
		$options = get_option('baskerville_settings', array());
		$mode = isset($options['ai_bot_blocking_mode']) ? $options['ai_bot_blocking_mode'] : 'allow_all';
		?>
		<fieldset>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="allow_all"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'allow_all'); ?> />
				<strong><?php esc_html_e('Allow All AI Bots', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('No AI bot restrictions (allow all companies)', 'baskerville-ai-security'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="block_all"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'block_all'); ?> />
				<strong class="baskerville-text-danger"><?php esc_html_e('Block All AI Bots', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Block all AI bot crawlers (no exceptions)', 'baskerville-ai-security'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="blacklist"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'blacklist'); ?> />
				<strong><?php esc_html_e('Block List', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Block access from specified companies', 'baskerville-ai-security'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="whitelist"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'whitelist'); ?> />
				<strong><?php esc_html_e('Allow List', 'baskerville-ai-security'); ?></strong> -
				<?php esc_html_e('Allow access ONLY from specified companies', 'baskerville-ai-security'); ?>
			</label>
		</fieldset>
		<p class="description">
			<?php esc_html_e('Choose whether to allow all AI bots, block all AI bots, block specific companies, or allow only specific companies.', 'baskerville-ai-security'); ?>
		</p>

		<?php
	}

	public function render_blacklist_ai_companies_field() {
		$options = get_option('baskerville_settings', array());
		$blacklist_companies = isset($options['blacklist_ai_companies']) ? $options['blacklist_ai_companies'] : '';

		// Parse selected companies from comma-separated string
		$selected_companies = array();
		if (!empty($blacklist_companies)) {
			$selected_companies = array_map('trim', explode(',', $blacklist_companies));
		}

		// Get list of known AI bot companies
		$companies = $this->get_ai_companies_list();
		?>
		<div>
			<select name="baskerville_settings[blacklist_ai_companies][]"
					id="baskerville_blacklist_ai_companies"
					class="baskerville-aibot-select baskerville-input-full"
					multiple="multiple">
				<?php foreach ($companies as $company): ?>
					<option value="<?php echo esc_attr($company); ?>"
							<?php echo in_array($company, $selected_companies) ? 'selected' : ''; ?>>
						<?php echo esc_html($company); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<p class="description">
				<strong class="baskerville-text-danger"><?php esc_html_e('Block access from these AI bot companies', 'baskerville-ai-security'); ?></strong><br>
				<?php esc_html_e('Search and select companies to block. You can select multiple companies.', 'baskerville-ai-security'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Block List" mode is selected above.', 'baskerville-ai-security'); ?></em>
			</p>
		</div>

		<?php
	}

	public function render_whitelist_ai_companies_field() {
		$options = get_option('baskerville_settings', array());
		$whitelist_companies = isset($options['whitelist_ai_companies']) ? $options['whitelist_ai_companies'] : '';

		// Parse selected companies from comma-separated string
		$selected_companies = array();
		if (!empty($whitelist_companies)) {
			$selected_companies = array_map('trim', explode(',', $whitelist_companies));
		}

		// Get list of known AI bot companies
		$companies = $this->get_ai_companies_list();
		?>
		<div>
			<select name="baskerville_settings[whitelist_ai_companies][]"
					id="baskerville_whitelist_ai_companies"
					class="baskerville-aibot-select baskerville-input-full"
					multiple="multiple">
				<?php foreach ($companies as $company): ?>
					<option value="<?php echo esc_attr($company); ?>"
							<?php echo in_array($company, $selected_companies) ? 'selected' : ''; ?>>
						<?php echo esc_html($company); ?>
					</option>
				<?php endforeach; ?>
			</select>
			<p class="description">
				<strong class="baskerville-text-primary"><?php esc_html_e('Allow access ONLY from these AI bot companies', 'baskerville-ai-security'); ?></strong><br>
				<?php esc_html_e('Search and select companies to allow. You can select multiple companies.', 'baskerville-ai-security'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Allow List" mode is selected above.', 'baskerville-ai-security'); ?></em>
			</p>
		</div>
		<?php
	}

	private function get_ai_companies_list() {
		return array(
			'OpenAI',
			'Anthropic',
			'Google',
			'Meta',
			'ByteDance',
			'Amazon',
			'Baidu',
			'Perplexity',
			'Cohere',
			'Common Crawl',
			'Huawei',
			'NetEase',
			'Generic',
			'Unknown',
		);
	}

	private function get_geoip_source_name() {
		if (!empty($_SERVER['GEOIP2_COUNTRY_CODE'])) {
			return 'NGINX (ngx_http_geoip2_module)';
		} elseif (!empty($_SERVER['GEOIP_COUNTRY_CODE'])) {
			return 'NGINX (legacy ngx_http_geoip_module)';
		} elseif (!empty($_SERVER['HTTP_X_COUNTRY_CODE'])) {
			return 'NGINX (custom X-Country-Code header)';
		} elseif (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
			return 'Cloudflare';
		}

		// Check MaxMind first
		$db_path = WP_CONTENT_DIR . '/uploads/geoip/GeoLite2-Country.mmdb';
		$autoload_path = BASKERVILLE_PLUGIN_PATH . 'vendor/autoload.php';
		if (file_exists($db_path) && file_exists($autoload_path)) {
			return 'MaxMind GeoLite2';
		}

		// Check Deflect GeoIP as fallback
		if (!class_exists('Baskerville_Deflect_GeoIP')) {
			$class_file = BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-deflect-geoip.php';
			if (file_exists($class_file)) {
				require_once $class_file;
			}
		}
		if (class_exists('Baskerville_Deflect_GeoIP')) {
			$deflect = new Baskerville_Deflect_GeoIP();
			if ($deflect->is_installed()) {
				return 'Deflect GeoIP';
			}
		}

		return 'None configured';
	}

	/**
	 * Get active GeoIP source with status
	 * Returns array with 'source' name and 'available' boolean
	 */
	private function get_active_geoip_source() {
		// Check server-side sources first
		if (!empty($_SERVER['GEOIP2_COUNTRY_CODE'])) {
			return array('source' => 'NGINX GeoIP2', 'available' => true, 'country' => sanitize_text_field(wp_unslash($_SERVER['GEOIP2_COUNTRY_CODE'])));
		}
		if (!empty($_SERVER['GEOIP_COUNTRY_CODE'])) {
			return array('source' => 'NGINX GeoIP (legacy)', 'available' => true, 'country' => sanitize_text_field(wp_unslash($_SERVER['GEOIP_COUNTRY_CODE'])));
		}
		if (!empty($_SERVER['HTTP_X_COUNTRY_CODE'])) {
			return array('source' => 'NGINX Custom Header', 'available' => true, 'country' => sanitize_text_field(wp_unslash($_SERVER['HTTP_X_COUNTRY_CODE'])));
		}
		if (!empty($_SERVER['HTTP_CF_IPCOUNTRY'])) {
			return array('source' => 'Cloudflare', 'available' => true, 'country' => sanitize_text_field(wp_unslash($_SERVER['HTTP_CF_IPCOUNTRY'])));
		}

		// Check MaxMind first (priority over Deflect)
		$db_path = WP_CONTENT_DIR . '/uploads/geoip/GeoLite2-Country.mmdb';
		$autoload_path = BASKERVILLE_PLUGIN_PATH . 'vendor/autoload.php';

		if (file_exists($db_path) && file_exists($autoload_path)) {
			// Try to load and test MaxMind
			if (!class_exists('GeoIp2\Database\Reader')) {
				require_once $autoload_path;
			}
			if (class_exists('GeoIp2\Database\Reader')) {
				// Try a test lookup
				try {
					$current_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
					$reader = new \GeoIp2\Database\Reader($db_path);
					$record = $reader->country($current_ip);
					return array('source' => 'MaxMind GeoLite2', 'available' => true, 'country' => $record->country->isoCode);
				} catch (\Exception $e) {
					return array('source' => 'MaxMind GeoLite2', 'available' => true, 'country' => null, 'note' => 'Configured but lookup failed');
				}
			}
		}

		// Check Deflect GeoIP as fallback
		if (!class_exists('Baskerville_Deflect_GeoIP')) {
			$class_file = BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-deflect-geoip.php';
			if (file_exists($class_file)) {
				require_once $class_file;
			}
		}
		if (class_exists('Baskerville_Deflect_GeoIP')) {
			$deflect = new Baskerville_Deflect_GeoIP();
			if ($deflect->is_installed()) {
				try {
					$current_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
					$country = $deflect->lookup($current_ip);
					return array('source' => 'Deflect GeoIP', 'available' => true, 'country' => $country);
				} catch (\Exception $e) {
					return array('source' => 'Deflect GeoIP', 'available' => true, 'country' => null, 'note' => 'Configured but lookup failed');
				}
			}
		}

		// Nothing available
		return array('source' => null, 'available' => false);
	}

	private function get_countries_list() {
		return array(
			'AF' => esc_html__('Afghanistan', 'baskerville-ai-security'),
			'AL' => esc_html__('Albania', 'baskerville-ai-security'),
			'DZ' => esc_html__('Algeria', 'baskerville-ai-security'),
			'AS' => esc_html__('American Samoa', 'baskerville-ai-security'),
			'AD' => esc_html__('Andorra', 'baskerville-ai-security'),
			'AO' => esc_html__('Angola', 'baskerville-ai-security'),
			'AI' => esc_html__('Anguilla', 'baskerville-ai-security'),
			'AQ' => esc_html__('Antarctica', 'baskerville-ai-security'),
			'AG' => esc_html__('Antigua and Barbuda', 'baskerville-ai-security'),
			'AR' => esc_html__('Argentina', 'baskerville-ai-security'),
			'AM' => esc_html__('Armenia', 'baskerville-ai-security'),
			'AW' => esc_html__('Aruba', 'baskerville-ai-security'),
			'AU' => esc_html__('Australia', 'baskerville-ai-security'),
			'AT' => esc_html__('Austria', 'baskerville-ai-security'),
			'AZ' => esc_html__('Azerbaijan', 'baskerville-ai-security'),
			'BS' => esc_html__('Bahamas', 'baskerville-ai-security'),
			'BH' => esc_html__('Bahrain', 'baskerville-ai-security'),
			'BD' => esc_html__('Bangladesh', 'baskerville-ai-security'),
			'BB' => esc_html__('Barbados', 'baskerville-ai-security'),
			'BY' => esc_html__('Belarus', 'baskerville-ai-security'),
			'BE' => esc_html__('Belgium', 'baskerville-ai-security'),
			'BZ' => esc_html__('Belize', 'baskerville-ai-security'),
			'BJ' => esc_html__('Benin', 'baskerville-ai-security'),
			'BM' => esc_html__('Bermuda', 'baskerville-ai-security'),
			'BT' => esc_html__('Bhutan', 'baskerville-ai-security'),
			'BO' => esc_html__('Bolivia', 'baskerville-ai-security'),
			'BA' => esc_html__('Bosnia and Herzegovina', 'baskerville-ai-security'),
			'BW' => esc_html__('Botswana', 'baskerville-ai-security'),
			'BR' => esc_html__('Brazil', 'baskerville-ai-security'),
			'BN' => esc_html__('Brunei', 'baskerville-ai-security'),
			'BG' => esc_html__('Bulgaria', 'baskerville-ai-security'),
			'BF' => esc_html__('Burkina Faso', 'baskerville-ai-security'),
			'BI' => esc_html__('Burundi', 'baskerville-ai-security'),
			'KH' => esc_html__('Cambodia', 'baskerville-ai-security'),
			'CM' => esc_html__('Cameroon', 'baskerville-ai-security'),
			'CA' => esc_html__('Canada', 'baskerville-ai-security'),
			'CV' => esc_html__('Cape Verde', 'baskerville-ai-security'),
			'KY' => esc_html__('Cayman Islands', 'baskerville-ai-security'),
			'CF' => esc_html__('Central African Republic', 'baskerville-ai-security'),
			'TD' => esc_html__('Chad', 'baskerville-ai-security'),
			'CL' => esc_html__('Chile', 'baskerville-ai-security'),
			'CN' => esc_html__('China', 'baskerville-ai-security'),
			'CO' => esc_html__('Colombia', 'baskerville-ai-security'),
			'KM' => esc_html__('Comoros', 'baskerville-ai-security'),
			'CG' => esc_html__('Congo', 'baskerville-ai-security'),
			'CD' => esc_html__('Congo (DRC)', 'baskerville-ai-security'),
			'CK' => esc_html__('Cook Islands', 'baskerville-ai-security'),
			'CR' => esc_html__('Costa Rica', 'baskerville-ai-security'),
			'CI' => esc_html__('Côte d\'Ivoire', 'baskerville-ai-security'),
			'HR' => esc_html__('Croatia', 'baskerville-ai-security'),
			'CU' => esc_html__('Cuba', 'baskerville-ai-security'),
			'CY' => esc_html__('Cyprus', 'baskerville-ai-security'),
			'CZ' => esc_html__('Czech Republic', 'baskerville-ai-security'),
			'DK' => esc_html__('Denmark', 'baskerville-ai-security'),
			'DJ' => esc_html__('Djibouti', 'baskerville-ai-security'),
			'DM' => esc_html__('Dominica', 'baskerville-ai-security'),
			'DO' => esc_html__('Dominican Republic', 'baskerville-ai-security'),
			'EC' => esc_html__('Ecuador', 'baskerville-ai-security'),
			'EG' => esc_html__('Egypt', 'baskerville-ai-security'),
			'SV' => esc_html__('El Salvador', 'baskerville-ai-security'),
			'GQ' => esc_html__('Equatorial Guinea', 'baskerville-ai-security'),
			'ER' => esc_html__('Eritrea', 'baskerville-ai-security'),
			'EE' => esc_html__('Estonia', 'baskerville-ai-security'),
			'ET' => esc_html__('Ethiopia', 'baskerville-ai-security'),
			'FK' => esc_html__('Falkland Islands', 'baskerville-ai-security'),
			'FO' => esc_html__('Faroe Islands', 'baskerville-ai-security'),
			'FJ' => esc_html__('Fiji', 'baskerville-ai-security'),
			'FI' => esc_html__('Finland', 'baskerville-ai-security'),
			'FR' => esc_html__('France', 'baskerville-ai-security'),
			'GF' => esc_html__('French Guiana', 'baskerville-ai-security'),
			'PF' => esc_html__('French Polynesia', 'baskerville-ai-security'),
			'GA' => esc_html__('Gabon', 'baskerville-ai-security'),
			'GM' => esc_html__('Gambia', 'baskerville-ai-security'),
			'GE' => esc_html__('Georgia', 'baskerville-ai-security'),
			'DE' => esc_html__('Germany', 'baskerville-ai-security'),
			'GH' => esc_html__('Ghana', 'baskerville-ai-security'),
			'GI' => esc_html__('Gibraltar', 'baskerville-ai-security'),
			'GR' => esc_html__('Greece', 'baskerville-ai-security'),
			'GL' => esc_html__('Greenland', 'baskerville-ai-security'),
			'GD' => esc_html__('Grenada', 'baskerville-ai-security'),
			'GP' => esc_html__('Guadeloupe', 'baskerville-ai-security'),
			'GU' => esc_html__('Guam', 'baskerville-ai-security'),
			'GT' => esc_html__('Guatemala', 'baskerville-ai-security'),
			'GN' => esc_html__('Guinea', 'baskerville-ai-security'),
			'GW' => esc_html__('Guinea-Bissau', 'baskerville-ai-security'),
			'GY' => esc_html__('Guyana', 'baskerville-ai-security'),
			'HT' => esc_html__('Haiti', 'baskerville-ai-security'),
			'HN' => esc_html__('Honduras', 'baskerville-ai-security'),
			'HK' => esc_html__('Hong Kong', 'baskerville-ai-security'),
			'HU' => esc_html__('Hungary', 'baskerville-ai-security'),
			'IS' => esc_html__('Iceland', 'baskerville-ai-security'),
			'IN' => esc_html__('India', 'baskerville-ai-security'),
			'ID' => esc_html__('Indonesia', 'baskerville-ai-security'),
			'IR' => esc_html__('Iran', 'baskerville-ai-security'),
			'IQ' => esc_html__('Iraq', 'baskerville-ai-security'),
			'IE' => esc_html__('Ireland', 'baskerville-ai-security'),
			'IL' => esc_html__('Israel', 'baskerville-ai-security'),
			'IT' => esc_html__('Italy', 'baskerville-ai-security'),
			'JM' => esc_html__('Jamaica', 'baskerville-ai-security'),
			'JP' => esc_html__('Japan', 'baskerville-ai-security'),
			'JO' => esc_html__('Jordan', 'baskerville-ai-security'),
			'KZ' => esc_html__('Kazakhstan', 'baskerville-ai-security'),
			'KE' => esc_html__('Kenya', 'baskerville-ai-security'),
			'KI' => esc_html__('Kiribati', 'baskerville-ai-security'),
			'KP' => esc_html__('North Korea', 'baskerville-ai-security'),
			'KR' => esc_html__('South Korea', 'baskerville-ai-security'),
			'KW' => esc_html__('Kuwait', 'baskerville-ai-security'),
			'KG' => esc_html__('Kyrgyzstan', 'baskerville-ai-security'),
			'LA' => esc_html__('Laos', 'baskerville-ai-security'),
			'LV' => esc_html__('Latvia', 'baskerville-ai-security'),
			'LB' => esc_html__('Lebanon', 'baskerville-ai-security'),
			'LS' => esc_html__('Lesotho', 'baskerville-ai-security'),
			'LR' => esc_html__('Liberia', 'baskerville-ai-security'),
			'LY' => esc_html__('Libya', 'baskerville-ai-security'),
			'LI' => esc_html__('Liechtenstein', 'baskerville-ai-security'),
			'LT' => esc_html__('Lithuania', 'baskerville-ai-security'),
			'LU' => esc_html__('Luxembourg', 'baskerville-ai-security'),
			'MO' => esc_html__('Macau', 'baskerville-ai-security'),
			'MK' => esc_html__('North Macedonia', 'baskerville-ai-security'),
			'MG' => esc_html__('Madagascar', 'baskerville-ai-security'),
			'MW' => esc_html__('Malawi', 'baskerville-ai-security'),
			'MY' => esc_html__('Malaysia', 'baskerville-ai-security'),
			'MV' => esc_html__('Maldives', 'baskerville-ai-security'),
			'ML' => esc_html__('Mali', 'baskerville-ai-security'),
			'MT' => esc_html__('Malta', 'baskerville-ai-security'),
			'MH' => esc_html__('Marshall Islands', 'baskerville-ai-security'),
			'MQ' => esc_html__('Martinique', 'baskerville-ai-security'),
			'MR' => esc_html__('Mauritania', 'baskerville-ai-security'),
			'MU' => esc_html__('Mauritius', 'baskerville-ai-security'),
			'YT' => esc_html__('Mayotte', 'baskerville-ai-security'),
			'MX' => esc_html__('Mexico', 'baskerville-ai-security'),
			'FM' => esc_html__('Micronesia', 'baskerville-ai-security'),
			'MD' => esc_html__('Moldova', 'baskerville-ai-security'),
			'MC' => esc_html__('Monaco', 'baskerville-ai-security'),
			'MN' => esc_html__('Mongolia', 'baskerville-ai-security'),
			'ME' => esc_html__('Montenegro', 'baskerville-ai-security'),
			'MS' => esc_html__('Montserrat', 'baskerville-ai-security'),
			'MA' => esc_html__('Morocco', 'baskerville-ai-security'),
			'MZ' => esc_html__('Mozambique', 'baskerville-ai-security'),
			'MM' => esc_html__('Myanmar', 'baskerville-ai-security'),
			'NA' => esc_html__('Namibia', 'baskerville-ai-security'),
			'NR' => esc_html__('Nauru', 'baskerville-ai-security'),
			'NP' => esc_html__('Nepal', 'baskerville-ai-security'),
			'NL' => esc_html__('Netherlands', 'baskerville-ai-security'),
			'NC' => esc_html__('New Caledonia', 'baskerville-ai-security'),
			'NZ' => esc_html__('New Zealand', 'baskerville-ai-security'),
			'NI' => esc_html__('Nicaragua', 'baskerville-ai-security'),
			'NE' => esc_html__('Niger', 'baskerville-ai-security'),
			'NG' => esc_html__('Nigeria', 'baskerville-ai-security'),
			'NU' => esc_html__('Niue', 'baskerville-ai-security'),
			'NF' => esc_html__('Norfolk Island', 'baskerville-ai-security'),
			'MP' => esc_html__('Northern Mariana Islands', 'baskerville-ai-security'),
			'NO' => esc_html__('Norway', 'baskerville-ai-security'),
			'OM' => esc_html__('Oman', 'baskerville-ai-security'),
			'PK' => esc_html__('Pakistan', 'baskerville-ai-security'),
			'PW' => esc_html__('Palau', 'baskerville-ai-security'),
			'PS' => esc_html__('Palestine', 'baskerville-ai-security'),
			'PA' => esc_html__('Panama', 'baskerville-ai-security'),
			'PG' => esc_html__('Papua New Guinea', 'baskerville-ai-security'),
			'PY' => esc_html__('Paraguay', 'baskerville-ai-security'),
			'PE' => esc_html__('Peru', 'baskerville-ai-security'),
			'PH' => esc_html__('Philippines', 'baskerville-ai-security'),
			'PL' => esc_html__('Poland', 'baskerville-ai-security'),
			'PT' => esc_html__('Portugal', 'baskerville-ai-security'),
			'PR' => esc_html__('Puerto Rico', 'baskerville-ai-security'),
			'QA' => esc_html__('Qatar', 'baskerville-ai-security'),
			'RE' => esc_html__('Réunion', 'baskerville-ai-security'),
			'RO' => esc_html__('Romania', 'baskerville-ai-security'),
			'RU' => esc_html__('Russia', 'baskerville-ai-security'),
			'RW' => esc_html__('Rwanda', 'baskerville-ai-security'),
			'WS' => esc_html__('Samoa', 'baskerville-ai-security'),
			'SM' => esc_html__('San Marino', 'baskerville-ai-security'),
			'ST' => esc_html__('São Tomé and Príncipe', 'baskerville-ai-security'),
			'SA' => esc_html__('Saudi Arabia', 'baskerville-ai-security'),
			'SN' => esc_html__('Senegal', 'baskerville-ai-security'),
			'RS' => esc_html__('Serbia', 'baskerville-ai-security'),
			'SC' => esc_html__('Seychelles', 'baskerville-ai-security'),
			'SL' => esc_html__('Sierra Leone', 'baskerville-ai-security'),
			'SG' => esc_html__('Singapore', 'baskerville-ai-security'),
			'SK' => esc_html__('Slovakia', 'baskerville-ai-security'),
			'SI' => esc_html__('Slovenia', 'baskerville-ai-security'),
			'SB' => esc_html__('Solomon Islands', 'baskerville-ai-security'),
			'SO' => esc_html__('Somalia', 'baskerville-ai-security'),
			'ZA' => esc_html__('South Africa', 'baskerville-ai-security'),
			'SS' => esc_html__('South Sudan', 'baskerville-ai-security'),
			'ES' => esc_html__('Spain', 'baskerville-ai-security'),
			'LK' => esc_html__('Sri Lanka', 'baskerville-ai-security'),
			'SD' => esc_html__('Sudan', 'baskerville-ai-security'),
			'SR' => esc_html__('Suriname', 'baskerville-ai-security'),
			'SZ' => esc_html__('Eswatini', 'baskerville-ai-security'),
			'SE' => esc_html__('Sweden', 'baskerville-ai-security'),
			'CH' => esc_html__('Switzerland', 'baskerville-ai-security'),
			'SY' => esc_html__('Syria', 'baskerville-ai-security'),
			'TW' => esc_html__('Taiwan', 'baskerville-ai-security'),
			'TJ' => esc_html__('Tajikistan', 'baskerville-ai-security'),
			'TZ' => esc_html__('Tanzania', 'baskerville-ai-security'),
			'TH' => esc_html__('Thailand', 'baskerville-ai-security'),
			'TL' => esc_html__('Timor-Leste', 'baskerville-ai-security'),
			'TG' => esc_html__('Togo', 'baskerville-ai-security'),
			'TK' => esc_html__('Tokelau', 'baskerville-ai-security'),
			'TO' => esc_html__('Tonga', 'baskerville-ai-security'),
			'TT' => esc_html__('Trinidad and Tobago', 'baskerville-ai-security'),
			'TN' => esc_html__('Tunisia', 'baskerville-ai-security'),
			'TR' => esc_html__('Turkey', 'baskerville-ai-security'),
			'TM' => esc_html__('Turkmenistan', 'baskerville-ai-security'),
			'TC' => esc_html__('Turks and Caicos Islands', 'baskerville-ai-security'),
			'TV' => esc_html__('Tuvalu', 'baskerville-ai-security'),
			'UG' => esc_html__('Uganda', 'baskerville-ai-security'),
			'UA' => esc_html__('Ukraine', 'baskerville-ai-security'),
			'AE' => esc_html__('United Arab Emirates', 'baskerville-ai-security'),
			'GB' => esc_html__('United Kingdom', 'baskerville-ai-security'),
			'US' => esc_html__('United States', 'baskerville-ai-security'),
			'UY' => esc_html__('Uruguay', 'baskerville-ai-security'),
			'UZ' => esc_html__('Uzbekistan', 'baskerville-ai-security'),
			'VU' => esc_html__('Vanuatu', 'baskerville-ai-security'),
			'VA' => esc_html__('Vatican City', 'baskerville-ai-security'),
			'VE' => esc_html__('Venezuela', 'baskerville-ai-security'),
			'VN' => esc_html__('Vietnam', 'baskerville-ai-security'),
			'VG' => esc_html__('British Virgin Islands', 'baskerville-ai-security'),
			'VI' => esc_html__('U.S. Virgin Islands', 'baskerville-ai-security'),
			'WF' => esc_html__('Wallis and Futuna', 'baskerville-ai-security'),
			'YE' => esc_html__('Yemen', 'baskerville-ai-security'),
			'ZM' => esc_html__('Zambia', 'baskerville-ai-security'),
			'ZW' => esc_html__('Zimbabwe', 'baskerville-ai-security'),
		);
	}

	private function render_geoip_status_banner() {
		$options = get_option('baskerville_settings', array());
		$mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';

		if ($mode === 'allow_all') {
			// Don't show banner if allowing all countries
			return;
		}

		// Get full country names map
		$all_countries = $this->get_countries_list();

		if ($mode === 'whitelist') {
			$countries = isset($options['whitelist_countries']) ? $options['whitelist_countries'] : '';
			if (empty($countries)) {
				return; // Don't show banner if no countries configured
			}
			$country_list = array_map('trim', explode(',', $countries));
			$country_count = count($country_list);

			// Convert country codes to full names
			$country_names = array();
			foreach ($country_list as $code) {
				$code = strtoupper($code);
				if (isset($all_countries[$code])) {
					$country_names[] = $all_countries[$code] . ' (' . $code . ')';
				} else {
					$country_names[] = $code; // Fallback to code if name not found
				}
			}
			$countries_display = implode(', ', $country_names);

			$banner_color = '#2271b1';
			$icon = '✓';
			$title = esc_html__('Allow List Mode Active', 'baskerville-ai-security');
			$description = sprintf(
				/* translators: %1$d is the number of countries, %2$s is either 'country' or 'countries', %3$s is the list of country names */
				esc_html__('Access is allowed ONLY from %1$d %2$s: %3$s', 'baskerville-ai-security'),
				esc_html( $country_count ),
				$country_count === 1 ? esc_html__('country', 'baskerville-ai-security') : esc_html__('countries', 'baskerville-ai-security'),
				'<strong>' . esc_html( $countries_display ) . '</strong>'
			);
		} else {
			// blacklist mode
			$countries = isset($options['blacklist_countries']) ? $options['blacklist_countries'] : '';
			if (empty($countries)) {
				return; // Don't show banner if no countries configured
			}
			$country_list = array_map('trim', explode(',', $countries));
			$country_count = count($country_list);

			// Convert country codes to full names
			$country_names = array();
			foreach ($country_list as $code) {
				$code = strtoupper($code);
				if (isset($all_countries[$code])) {
					$country_names[] = $all_countries[$code] . ' (' . $code . ')';
				} else {
					$country_names[] = $code; // Fallback to code if name not found
				}
			}
			$countries_display = implode(', ', $country_names);

			$banner_color = '#d32f2f';
			$icon = '✕';
			$title = esc_html__('Block List Mode Active', 'baskerville-ai-security');
			$description = sprintf(
				/* translators: %1$d is the number of countries, %2$s is either 'country' or 'countries', %3$s is the list of country names */
				esc_html__('Access is blocked from %1$d %2$s: %3$s', 'baskerville-ai-security'),
				esc_html( $country_count ),
				$country_count === 1 ? esc_html__('country', 'baskerville-ai-security') : esc_html__('countries', 'baskerville-ai-security'),
				'<strong>' . esc_html( $countries_display ) . '</strong>'
			);
		}
		?>
		<div class="baskerville-banner" style="background: <?php echo esc_attr($banner_color); ?>;">
			<div class="baskerville-banner-icon">
				<?php echo esc_html($icon); ?>
			</div>
			<div class="baskerville-banner-content">
				<div class="baskerville-banner-title">
					<?php echo esc_html($title); ?>
				</div>
				<div class="baskerville-banner-description">
					<?php echo wp_kses_post($description); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Get traffic statistics for specified period.
	 *
	 * Direct database queries are required for real-time admin statistics.
	 * Caching is not applicable as data changes frequently.
	 *
	 * @param string $period Time period (12h, 1day, 3days, 7days).
	 * @return array Traffic statistics array.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	private function get_traffic_stats($period = '1day') {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';

		// Calculate time range based on period
		$hours_map = array(
			'12h' => 12,
			'1day' => 24,
			'3days' => 72,
			'7days' => 168
		);

		$hours = isset($hours_map[$period]) ? $hours_map[$period] : 24;
		$time_threshold = gmdate('Y-m-d H:i:s', time() - ($hours * 3600));

		// Total visits

		$total_visits = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM %i WHERE timestamp_utc >= %s",
				$table,
				$time_threshold
			)
		);

		// Total unique IPs

		$total_ips = (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s",
			$table,
			$time_threshold
		)
	);

		// Blocked IPs (unique IPs that have block_reason)

		$blocked_ips = (int) $wpdb->get_var(
		$wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s AND block_reason IS NOT NULL AND block_reason != ''",
			$table,
			$time_threshold
		)
	);

		// Calculate block rate
		$block_rate = $total_ips > 0 ? round(($blocked_ips / $total_ips) * 100, 2) : 0;

		return array(
			'total_visits' => $total_visits,
			'total_ips'    => $total_ips,
			'blocked_ips'  => $blocked_ips,
			'block_rate'   => $block_rate,
			'hours'        => $hours
		);
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery

	/**
	 * Get timeseries data for charts.
	 *
	 * Direct database queries are required for real-time admin charts.
	 * Caching is not applicable as data changes frequently.
	 *
	 * @param int $hours Number of hours to retrieve data for.
	 * @return array Country statistics array.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	private function get_timeseries_data($hours = 24) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'baskerville_stats';

		$hours  = max(1, min(720, (int)$hours));
		$cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

		// Determine bucket size based on time period
		// 12h = 15min, 24h = 30min, 3days = 1h, 7days = 2h
		if ($hours <= 12) {
			$bucket_seconds = 900;  // 15 minutes
		} elseif ($hours <= 24) {
			$bucket_seconds = 1800; // 30 minutes
		} elseif ($hours <= 72) {
			$bucket_seconds = 3600; // 1 hour
		} else {
			$bucket_seconds = 7200; // 2 hours
		}

	
		$results = $wpdb->get_results($wpdb->prepare(
			"SELECT
				FROM_UNIXTIME(
				FLOOR(UNIX_TIMESTAMP(timestamp_utc) / %d) * %d
				) AS time_slot,
				COUNT(*) AS total_visits,
				SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) AS human_count,
				SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_count,
				SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_count,
				SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_count,
				SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
				AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score
			FROM %i
			WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
			GROUP BY time_slot
			ORDER BY time_slot ASC",
			$bucket_seconds,
			$bucket_seconds,
			$table_name,
			$cutoff
		), ARRAY_A);

		$out = [];
		foreach ($results ?: [] as $r) {
			$total    = (int)$r['total_visits'];
			$humanCnt = (int)$r['human_count'];
			$humanPct = $total > 0 ? round(($humanCnt * 100.0) / $total, 2) : 0;

			$out[] = [
				'time'               => $r['time_slot'],
				'total_visits'       => $total,
				'human_count'        => $humanCnt,
				'bad_bot_count'      => (int)$r['bad_bot_count'],
				'ai_bot_count'       => (int)$r['ai_bot_count'],
				'bot_count'          => (int)$r['bot_count'],
				'verified_bot_count' => (int)$r['verified_bot_count'],
				'avg_score'          => $r['avg_score'] !== null ? round((float)$r['avg_score'], 2) : null,
				'human_percentage'   => $humanPct
			];
		}

		return $out;
	}

	/**
	 * Get Turnstile challenge timeseries data for charts
	 * @param int $hours Number of hours to look back
	 * @return array Timeseries data with pass/fail counts and precision
	 */
	private function get_turnstile_timeseries_data($hours = 24) {
		global $wpdb;
		$table_name = $wpdb->prefix . 'baskerville_stats';

		$hours  = max(1, min(720, (int)$hours));
		$cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

		// Determine bucket size based on time period
		if ($hours <= 12) {
			$bucket_seconds = 900;  // 15 minutes
		} elseif ($hours <= 24) {
			$bucket_seconds = 1800; // 30 minutes
		} elseif ($hours <= 72) {
			$bucket_seconds = 3600; // 1 hour
		} else {
			$bucket_seconds = 7200; // 2 hours
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$results = $wpdb->get_results($wpdb->prepare(
			"SELECT
				FROM_UNIXTIME(
				FLOOR(UNIX_TIMESTAMP(timestamp_utc) / %d) * %d
				) AS time_slot,
				SUM(CASE WHEN event_type='ts_redir' THEN 1 ELSE 0 END) AS redirect_count,
				SUM(CASE WHEN event_type='ts_pass' THEN 1 ELSE 0 END) AS pass_count,
				SUM(CASE WHEN event_type='ts_fail' THEN 1 ELSE 0 END) AS fail_count
			FROM %i
			WHERE event_type IN ('ts_redir', 'ts_pass', 'ts_fail')
			AND timestamp_utc >= %s
			GROUP BY time_slot
			ORDER BY time_slot ASC",
			$bucket_seconds,
			$bucket_seconds,
			$table_name,
			$cutoff
		), ARRAY_A);

		$out = [];
		$total_redirects = 0;
		$total_passes = 0;
		$total_fails = 0;

		foreach ($results ?: [] as $r) {
			$redirects = (int)$r['redirect_count'];
			$passes = (int)$r['pass_count'];
			$fails = (int)$r['fail_count'];
			// Precision = % who did NOT pass = (redirects - passes) / redirects
			$precision = $redirects > 0 ? round((($redirects - $passes) * 100.0) / $redirects, 1) : 0;

			$total_redirects += $redirects;
			$total_passes += $passes;
			$total_fails += $fails;

			$out[] = [
				'time'           => $r['time_slot'],
				'redirect_count' => $redirects,
				'pass_count'     => $passes,
				'fail_count'     => $fails,
				'precision'      => $precision,
			];
		}

		// Calculate total precision = % who did NOT pass
		$total_precision = $total_redirects > 0 ? round((($total_redirects - $total_passes) * 100.0) / $total_redirects, 1) : 0;

		return [
			'timeseries'      => $out,
			'total_redirects' => $total_redirects,
			'total_passes'    => $total_passes,
			'total_fails'     => $total_fails,
			'total_precision' => $total_precision,
		];
	}

	/**
	 * Get key metrics for analytics dashboard.
	 * Returns Block Rate, Challenge Rate, and Passed Challenge Rate.
	 */
	private function get_key_metrics($hours = 24) {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';
		$cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

		// Total unique IPs
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$total_ips = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s",
			$table,
			$cutoff
		));

		// Blocked unique IPs (has block_reason)
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$blocked_ips = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s AND block_reason IS NOT NULL AND block_reason != ''",
			$table,
			$cutoff
		));

		// Challenged unique IPs (ts_redir events)
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$challenged_ips = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s AND event_type = 'ts_redir'",
			$table,
			$cutoff
		));

		// Passed unique IPs (ts_pass events)
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
		$passed_ips = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(DISTINCT ip) FROM %i WHERE timestamp_utc >= %s AND event_type = 'ts_pass'",
			$table,
			$cutoff
		));

		// Calculate rates (all based on unique IPs)
		$block_rate = $total_ips > 0 ? round(($blocked_ips * 100.0) / $total_ips, 1) : 0;
		$challenge_rate = $total_ips > 0 ? round(($challenged_ips * 100.0) / $total_ips, 1) : 0;
		$pass_rate = $challenged_ips > 0 ? round(($passed_ips * 100.0) / $challenged_ips, 1) : 0;

		return [
			'total_ips'      => $total_ips,
			'blocked_ips'    => $blocked_ips,
			'challenged_ips' => $challenged_ips,
			'passed_ips'     => $passed_ips,
			'block_rate'     => $block_rate,
			'challenge_rate' => $challenge_rate,
			'pass_rate'      => $pass_rate,
		];
	}

	private function get_country_stats($hours = 24) {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';

		$cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

		// Get stats grouped by country_code directly from database
		$results = $wpdb->get_results($wpdb->prepare(
			"SELECT
				COALESCE(NULLIF(country_code, ''), 'XX') as country_code,
				COUNT(*) as total_requests,
				SUM(CASE WHEN event_type = 'block' OR (block_reason IS NOT NULL AND block_reason != '') THEN 1 ELSE 0 END) as blocked_requests
			FROM %i
			WHERE timestamp_utc >= %s
			GROUP BY country_code
			ORDER BY total_requests DESC",
			$table,
			$cutoff
		), ARRAY_A);

		$all_countries = $this->get_countries_list();

		// Build country stats
		$country_stats = array();
		foreach ($results as $row) {
			$country_code = strtoupper($row['country_code']);

			if ($country_code === 'XX') {
				$country_name = esc_html__('Unknown', 'baskerville-ai-security');
			} else {
				$country_name = isset($all_countries[$country_code]) ? $all_countries[$country_code] : $country_code;
			}

			$country_stats[] = array(
				'code' => $country_code,
				'name' => $country_name,
				'total' => (int)$row['total_requests'],
				'blocked' => (int)$row['blocked_requests']
			);
		}

		return $country_stats;
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery

	private function render_countries_tab() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required for read-only period filter parameter
		$period = isset($_GET['period']) ? sanitize_text_field(wp_unslash($_GET['period'])) : '1day';
		$valid_periods = array('12h', '1day', '3days', '7days');
		if (!in_array($period, $valid_periods)) {
			$period = '1day';
		}

		$hours_map = array(
			'12h' => 12,
			'1day' => 24,
			'3days' => 72,
			'7days' => 168
		);
		$hours = $hours_map[$period];

		// Build URLs for period buttons
		$base_url = admin_url('admin.php?page=baskerville-country-control');

		// Get country stats
		$country_stats = $this->get_country_stats($hours);

		// Get current GeoIP settings
		$options = get_option('baskerville_settings', array());
		$geoip_mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';
		$blacklist_countries = isset($options['blacklist_countries']) ? array_map('trim', explode(',', $options['blacklist_countries'])) : array();
		$whitelist_countries = isset($options['whitelist_countries']) ? array_map('trim', explode(',', $options['whitelist_countries'])) : array();

		?>
		<div class="countries-stats-container">
			<!-- Period Filter Buttons -->
			<div class="countries-period-filters">
				<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
				   class="countries-period-btn <?php echo $period === '12h' ? 'active' : ''; ?>">
					12h
				</a>
				<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
				   class="countries-period-btn <?php echo $period === '1day' ? 'active' : ''; ?>">
					1 day
				</a>
				<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
				   class="countries-period-btn <?php echo $period === '3days' ? 'active' : ''; ?>">
					3 days
				</a>
				<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
				   class="countries-period-btn <?php echo $period === '7days' ? 'active' : ''; ?>">
					7 days
				</a>
			</div>

			<?php if (!empty($country_stats)): ?>
				<!-- Charts Section -->
				<div class="baskerville-grid-2">
					<div class="baskerville-chart-card">
						<canvas id="baskervilleCountryTrafficChart"></canvas>
					</div>
					<div class="baskerville-chart-card">
						<canvas id="baskervilleCountryBansChart"></canvas>
					</div>
				</div>

				<!-- Country Stats Table -->
				<div class="country-stats-table">
					<h3><?php esc_html_e('Traffic by Country', 'baskerville-ai-security'); ?></h3>
					<table>
						<thead>
							<tr>
								<th><?php esc_html_e('Country', 'baskerville-ai-security'); ?></th>
								<th><?php esc_html_e('Total Requests', 'baskerville-ai-security'); ?></th>
								<th><?php esc_html_e('Blocked (403)', 'baskerville-ai-security'); ?></th>
								<th><?php esc_html_e('Block Rate', 'baskerville-ai-security'); ?></th>
								<th><?php esc_html_e('Access Status', 'baskerville-ai-security'); ?></th>
							</tr>
						</thead>
						<tbody>
							<?php foreach ($country_stats as $stat):
								$block_rate = $stat['total'] > 0 ? round(($stat['blocked'] / $stat['total']) * 100, 1) : 0;

								// Determine access status based on GeoIP mode
								$access_allowed = true; // Default for allow_all
								$status_label = '';
								$status_color = '';
								$status_icon = '';

								if ($stat['code'] === 'XX') {
									// Unknown country
									$status_label = __('Unknown', 'baskerville-ai-security');
									$status_color = '#999';
									$status_icon = '❓';
								} elseif ($geoip_mode === 'allow_all') {
									$access_allowed = true;
									$status_label = __('Allowed', 'baskerville-ai-security');
									$status_color = '#4CAF50';
									$status_icon = '✅';
								} elseif ($geoip_mode === 'blacklist') {
									$is_in_blacklist = in_array($stat['code'], $blacklist_countries);
									$access_allowed = !$is_in_blacklist;
									if ($is_in_blacklist) {
										$status_label = __('Blocked (Block List)', 'baskerville-ai-security');
										$status_color = '#d32f2f';
										$status_icon = '🚫';
									} else {
										$status_label = __('Allowed', 'baskerville-ai-security');
										$status_color = '#4CAF50';
										$status_icon = '✅';
									}
								} elseif ($geoip_mode === 'whitelist') {
									$is_in_whitelist = in_array($stat['code'], $whitelist_countries);
									$access_allowed = $is_in_whitelist;
									if ($is_in_whitelist) {
										$status_label = __('Allowed (Allow List)', 'baskerville-ai-security');
										$status_color = '#4CAF50';
										$status_icon = '✅';
									} else {
										$status_label = __('Blocked', 'baskerville-ai-security');
										$status_color = '#d32f2f';
										$status_icon = '🚫';
									}
								}
							?>
							<tr>
								<td>
									<strong><?php echo esc_html($stat['name']); ?></strong> (<?php echo esc_html($stat['code']); ?>)
								</td>
								<td><?php echo number_format($stat['total']); ?></td>
								<td class="<?php echo $stat['blocked'] > 0 ? 'baskerville-table-row-blocked' : 'baskerville-table-row-muted'; ?>">
									<?php echo number_format($stat['blocked']); ?>
								</td>
								<td>
									<?php
									$rate_class = 'baskerville-rate-low';
									if ($block_rate > 50) {
										$rate_class = 'baskerville-rate-high';
									} elseif ($block_rate > 20) {
										$rate_class = 'baskerville-rate-medium';
									}
									?>
									<span class="<?php echo esc_attr($rate_class); ?>">
										<?php echo esc_html($block_rate); ?>%
									</span>
								</td>
								<td>
									<?php
									$status_class = 'baskerville-status-unknown';
									if ($status_color === '#4CAF50') {
										$status_class = 'baskerville-status-allowed';
									} elseif ($status_color === '#d32f2f') {
										$status_class = 'baskerville-status-blocked';
									}
									?>
									<span class="<?php echo esc_attr($status_class); ?>">
										<?php echo esc_html($status_icon); ?> <?php echo esc_html($status_label); ?>
									</span>
								</td>
							</tr>
							<?php endforeach; ?>
						</tbody>
					</table>
				</div>
			<?php else: ?>
				<div class="baskerville-card-white-lg">
					<p><?php esc_html_e('No traffic data available for the selected period.', 'baskerville-ai-security'); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<?php if ( ! empty( $country_stats ) ) : ?>
		<?php
		wp_add_inline_script(
			'baskerville-admin',
			'window.baskervilleCountryData = ' . wp_json_encode( $country_stats ) . ';'
			. 'window.baskervilleCountryHours = ' . absint( $hours ) . ';',
			'before'
		);
		?>
		<?php endif; ?>
		<?php
	}

	private function render_traffic_tab() {
		// Get selected period from URL, default to 1day
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required for read-only period filter parameter
		$period = isset($_GET['period']) ? sanitize_text_field(wp_unslash($_GET['period'])) : '1day';
		$valid_periods = array('12h', '1day', '3days', '7days');
		if (!in_array($period, $valid_periods)) {
			$period = '1day';
		}

		$stats = $this->get_traffic_stats($period);

		// Build URLs for period buttons
		$base_url = admin_url('admin.php?page=baskerville-settings');
		?>

		<!-- Real-time Live Dashboard -->
		<div class="baskerville-live-dashboard">
			<h2 class="baskerville-dashboard-header">
				<span class="dashicons dashicons-visibility" ></span>
				<?php esc_html_e('Live Bot Attack Dashboard', 'baskerville-ai-security'); ?>
				<span class="live-indicator"></span>
			</h2>

			<!-- Live Stats Cards -->
			<div class="live-stats-grid">
				<div class="live-stat-card baskerville-gradient-purple">
					<div class="stat-icon">🛡️</div>
					<div class="stat-value" id="blocks-today">...</div>
					<div class="stat-label"><?php esc_html_e('Blocked Today', 'baskerville-ai-security'); ?></div>
				</div>

				<div class="live-stat-card baskerville-gradient-pink">
					<div class="stat-icon">⚡</div>
					<div class="stat-value" id="blocks-hour">...</div>
					<div class="stat-label"><?php esc_html_e('Blocked Last Hour', 'baskerville-ai-security'); ?></div>
				</div>

				<div class="live-stat-card baskerville-gradient-blue">
					<div class="stat-icon">🌍</div>
					<div class="stat-value" id="top-country">...</div>
					<div class="stat-label"><?php esc_html_e('Top Country Blocked', 'baskerville-ai-security'); ?></div>
				</div>
			</div>

			<!-- Live Feed -->
			<div class="live-feed-container">
				<div class="live-feed">
				<h3 class="baskerville-heading-flex">
						<span class="dashicons dashicons-admin-site"></span>
						<?php esc_html_e('Live Feed', 'baskerville-ai-security'); ?>
						<span class="feed-header-info"><?php esc_html_e('Auto-refresh: 10s', 'baskerville-ai-security'); ?></span>
					</h3>
					<div id="live-feed-items" class="baskerville-font-sm">
						<div class="baskerville-loading">
							<span class="dashicons dashicons-update baskerville-loading-spinner"></span>
							<p><?php esc_html_e('Loading live data...', 'baskerville-ai-security'); ?></p>
						</div>
					</div>
				</div>

				<div class="top-attackers">
					<h3 class="baskerville-heading-flex">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e('Top Attackers', 'baskerville-ai-security'); ?>
					</h3>
					<div id="top-attackers-list" class="baskerville-font-sm">
						<div class="baskerville-loading">
							<?php esc_html_e('Loading...', 'baskerville-ai-security'); ?>
						</div>
					</div>
				</div>
			</div>
		</div>


		<div class="baskerville-traffic-stats">
			<!-- Period Filter Buttons -->
			<div class="baskerville-period-filters">
				<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
				   class="baskerville-period-btn <?php echo $period === '12h' ? 'active' : ''; ?>">
					12h
				</a>
				<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
				   class="baskerville-period-btn <?php echo $period === '1day' ? 'active' : ''; ?>">
					1 day
				</a>
				<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
				   class="baskerville-period-btn <?php echo $period === '3days' ? 'active' : ''; ?>">
					3 days
				</a>
				<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
				   class="baskerville-period-btn <?php echo $period === '7days' ? 'active' : ''; ?>">
					7 days
				</a>
			</div>

			<!-- Stats Cards -->
			<div class="baskerville-stats-grid">
				<div class="baskerville-stat-card stat-grey">
					<div class="stat-value"><?php echo number_format($stats['total_visits']); ?></div>
					<div class="stat-label"><?php esc_html_e('Total Visits', 'baskerville-ai-security'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-dark-grey">
					<div class="stat-value"><?php echo number_format($stats['total_ips']); ?></div>
					<div class="stat-label"><?php esc_html_e('Total IPs', 'baskerville-ai-security'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-red">
					<div class="stat-value"><?php echo number_format($stats['blocked_ips']); ?></div>
					<div class="stat-label"><?php esc_html_e('IPs Blocked', 'baskerville-ai-security'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-red">
					<div class="stat-value"><?php echo esc_html($stats['block_rate']); ?>%</div>
					<div class="stat-label"><?php esc_html_e('Block Rate', 'baskerville-ai-security'); ?></div>
				</div>
			</div>

			<!-- Logging Status -->
			<?php
			$options = get_option('baskerville_settings', array());
			$log_mode = isset($options['log_mode']) ? $options['log_mode'] : 'database';
			?>
			<?php if ($log_mode === 'database'): ?>
			<div class="notice notice-success inline baskerville-notice">
				<h3 class="baskerville-section-title">
					<span class="dashicons dashicons-database"></span>
					<?php esc_html_e('Logging Status', 'baskerville-ai-security'); ?>
				</h3>
				<p>
					<strong><?php esc_html_e('Mode:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e( 'Direct to Database', 'baskerville-ai-security' ); ?><br>
					<span class="baskerville-text-success">✓</span> <?php esc_html_e( 'Logs are written directly to the database. No import needed, charts update in real-time.', 'baskerville-ai-security' ); ?><br>
					<br>
					💡 <strong><?php esc_html_e( 'Note:', 'baskerville-ai-security' ); ?></strong> <?php esc_html_e( 'This mode is slower (~500ms per request) but ensures data is always up-to-date. Consider switching to "File logging" mode for better performance on high-traffic sites.', 'baskerville-ai-security' ); ?>
				</p>
			</div>
			<?php elseif ($log_mode === 'file'):
				$stats_obj = new Baskerville_Stats(new Baskerville_Core(), new Baskerville_AI_UA(new Baskerville_Core()));
				$log_dir = $stats_obj->get_log_dir();
				$pending_files = 0;
				if (is_dir($log_dir)) {
					$files = glob($log_dir . '/visits-*.log');
					$pending_files = $files ? count($files) - 1 : 0; // -1 for today's file
					$pending_files = max(0, $pending_files);
				}
				$next_cron = wp_next_scheduled('baskerville_process_log_files');

				// Check if WP-Cron is disabled
				$wp_cron_disabled = defined('DISABLE_WP_CRON') && DISABLE_WP_CRON;

				// Get last successful import (we'll store this in options)
				$last_import = get_option('baskerville_last_log_import', 0);
				$last_import_time = $last_import ? human_time_diff($last_import, time()) . ' ago' : 'Never';

				// Determine cron health
				$cron_health = 'good';
				$cron_message = '';
				if (!$next_cron) {
					$cron_health = 'error';
					$cron_message = '⚠️ ' . esc_html__( 'Auto-import not scheduled!', 'baskerville-ai-security' );
				} elseif ($wp_cron_disabled) {
					$cron_health = 'warning';
					$cron_message = '⚠️ ' . esc_html__( 'WP-Cron is disabled (DISABLE_WP_CRON=true). You must set up a real cron job.', 'baskerville-ai-security' );
				} elseif ($pending_files > 5) {
					$cron_health = 'warning';
					$cron_message = '⚠️ ' . esc_html__( 'Many pending files - cron might not be running frequently.', 'baskerville-ai-security' );
				}
			?>
			<div class="notice notice-<?php echo $cron_health === 'good' ? 'info' : ($cron_health === 'error' ? 'error' : 'warning'); ?> inline baskerville-notice">
				<h3 class="baskerville-section-title">
					<span class="dashicons dashicons-database-import"></span>
					<?php esc_html_e('Log File Import Status', 'baskerville-ai-security'); ?>
				</h3>
				<table class="baskerville-simple-table">
					<tr>
						<td><strong><?php esc_html_e('Logging Mode:', 'baskerville-ai-security'); ?></strong></td>
						<td class="baskerville-td-padded"><?php esc_html_e( 'File logging (for performance)', 'baskerville-ai-security' ); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Pending log files:', 'baskerville-ai-security'); ?></strong></td>
						<td class="baskerville-td-padded"><?php echo esc_html($pending_files); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Last import:', 'baskerville-ai-security'); ?></strong></td>
						<td class="baskerville-td-padded"><?php echo esc_html($last_import_time); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('WP-Cron status:', 'baskerville-ai-security'); ?></strong></td>
						<td class="baskerville-td-padded">
							<?php if ($wp_cron_disabled): ?>
								<span class="baskerville-text-danger">❌ <?php esc_html_e( 'Disabled (DISABLE_WP_CRON=true)', 'baskerville-ai-security' ); ?></span>
							<?php else: ?>
								<span class="baskerville-text-success">✓ <?php esc_html_e( 'Enabled', 'baskerville-ai-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ($next_cron): ?>
					<tr>
						<td><strong><?php esc_html_e('Next auto-import:', 'baskerville-ai-security'); ?></strong></td>
						<td class="baskerville-td-padded"><?php
						printf(
							/* translators: %s: human-readable time difference */
							esc_html__( '%s from now', 'baskerville-ai-security' ),
							esc_html( human_time_diff( $next_cron, time() ) )
						);
						?></td>
					</tr>
					<?php endif; ?>
				</table>

				<?php if ($cron_message): ?>
					<div class="baskerville-warning-box <?php echo $cron_health === 'error' ? 'baskerville-warning-box-pink' : 'baskerville-warning-box-yellow'; ?>">
						<?php echo esc_html($cron_message); ?>
						<?php if ($wp_cron_disabled): ?>
							<br><br>
							<strong><?php esc_html_e( 'Fix:', 'baskerville-ai-security' ); ?></strong> <?php esc_html_e( 'Add this to your server crontab:', 'baskerville-ai-security' ); ?><br>
							<code class="baskerville-code">
								* * * * * wget -q -O - <?php echo esc_url(site_url('wp-cron.php?doing_wp_cron')); ?> &>/dev/null || curl -s <?php echo esc_url(site_url('wp-cron.php?doing_wp_cron')); ?> &>/dev/null
							</code>
						<?php endif; ?>
					</div>
				<?php endif; ?>

				<button type="button" class="button button-primary" id="import-logs-now">
					<?php esc_html_e('Import Logs Now', 'baskerville-ai-security'); ?>
				</button>
				<span id="import-logs-result" class="baskerville-ml-10"></span>

				<p class="baskerville-mt-15 baskerville-font-xs">
					💡 <strong><?php esc_html_e( 'Tip:', 'baskerville-ai-security' ); ?></strong> <?php esc_html_e( 'Auto-import runs every minute. If you have many visitors, consider switching to "Direct to Database" mode in Settings (slower but no import delay).', 'baskerville-ai-security' ); ?>
				</p>
			</div>
			<?php elseif ($log_mode === 'disabled'): ?>
			<div class="notice notice-warning inline baskerville-notice">
				<h3 class="baskerville-section-title">
					<span class="dashicons dashicons-warning"></span>
					<?php esc_html_e('Logging Status', 'baskerville-ai-security'); ?>
				</h3>
				<p>
					<strong><?php esc_html_e('Mode:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e( 'Disabled', 'baskerville-ai-security'); ?><br>
					<span class="baskerville-text-danger">⚠️</span> <?php esc_html_e( 'Logging is completely disabled. No statistics or charts will be available.', 'baskerville-ai-security'); ?><br>
					<br>
					💡 <?php esc_html_e( 'Go to Settings tab to enable logging (either "File logging" or "Direct to Database").', 'baskerville-ai-security'); ?>
				</p>
			</div>
			<?php endif; ?>
		</div>

		<?php
	}

	private function render_ai_bots_tab() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['ai_bot_control_enabled']) ? $options['ai_bot_control_enabled'] : true;
		// Header removed - slider at top
		?><?php

		// Get selected period from URL, default to 1day
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required for read-only period filter parameter
		$period = isset($_GET['period']) ? sanitize_text_field(wp_unslash($_GET['period'])) : '1day';
		$valid_periods = array('12h', '1day', '3days', '7days');
		if (!in_array($period, $valid_periods)) {
			$period = '1day';
		}

		// Convert period to hours
		$hours_map = array(
			'12h' => 12,
			'1day' => 24,
			'3days' => 72,
			'7days' => 168,
		);
		$hours = $hours_map[$period];

		// Get AI bots timeseries data
		try {
			// Fallback: initialize stats if not set (for backwards compatibility)
			if (!$this->stats) {
				$core = new Baskerville_Core();
				$aiua = new Baskerville_AI_UA($core);
				$this->stats = new Baskerville_Stats($core, $aiua);
				$this->aiua = $aiua;
			}

			$data = $this->stats->get_ai_bots_timeseries($hours);

			if (!is_array($data)) {
				throw new Exception('Invalid data format returned from get_ai_bots_timeseries');
			}

		} catch (Exception $e) {
			?>
			<div class="notice notice-error">
				<p><strong><?php esc_html_e( 'Error loading AI bots data:', 'baskerville-ai-security' ); ?></strong></p>
				<p><?php echo esc_html($e->getMessage()); ?></p>
			</div>
			<?php
			return;
		} catch (Error $e) {
			?>
			<div class="notice notice-error">
				<p><strong><?php esc_html_e( 'Fatal error loading AI bots data:', 'baskerville-ai-security' ); ?></strong></p>
				<p><?php echo esc_html($e->getMessage()); ?></p>
			</div>
			<?php
			return;
		}

		// Build URLs for period buttons
		$base_url = admin_url('admin.php?page=baskerville-ai-bot-control');

		// Check if we have any data
		$has_data = !empty($data['companies']) && count($data['companies']) > 0;
		?>

		<div class="baskerville-ai-bots-dashboard">
			<h2 class="baskerville-dashboard-header">
				<span class="dashicons dashicons-chart-bar" ></span>
				<?php esc_html_e('AI Bots Activity', 'baskerville-ai-security'); ?>
			</h2>

			<!-- Period Selection Buttons -->
			<div class="period-buttons">
				<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
				   class="button <?php echo $period === '12h' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('12h', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
				   class="button <?php echo $period === '1day' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('1 day', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
				   class="button <?php echo $period === '3days' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('3 days', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
				   class="button <?php echo $period === '7days' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('7 days', 'baskerville-ai-security'); ?>
				</a>
			</div>

			<?php if (!$has_data): ?>
				<div class="notice notice-info">
					<p><?php esc_html_e('No AI bot activity detected in the selected period.', 'baskerville-ai-security'); ?></p>
				</div>
			<?php else: ?>

			<!-- Chart Container -->
			<div class="chart-container">
				<canvas id="aiBotsChart"></canvas>
			</div>

			<?php
			wp_add_inline_script('baskerville-admin', 'window.baskervilleAIBotData = ' . wp_json_encode($data) . ';', 'before');
			?>

			<?php endif; ?>

		</div>

		<?php
	}

	public function ajax_install_maxmind() {
		check_ajax_referer('baskerville_install_maxmind', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville-ai-security')));
		}

		$installer = new Baskerville_MaxMind_Installer();
		$result = $installer->install();

		if ($result['success']) {
			wp_send_json_success($result);
		} else {
			wp_send_json_error($result);
		}
	}

	public function ajax_update_deflect_geoip() {
		check_ajax_referer('baskerville_update_deflect_geoip', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville-ai-security')));
		}

		if (!class_exists('Baskerville_Deflect_GeoIP')) {
			$class_file = BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-deflect-geoip.php';
			if (file_exists($class_file)) {
				require_once $class_file;
			} else {
				wp_send_json_error(array('message' => esc_html__('Deflect GeoIP module not available.', 'baskerville-ai-security')));
			}
		}

		$deflect = new Baskerville_Deflect_GeoIP();
		$force = isset($_POST['force']) && $_POST['force'] === 'true';
		$result = $deflect->update($force);

		if ($result['success']) {
			$stats = $deflect->get_stats();
			$result['stats'] = $stats;
			wp_send_json_success($result);
		} else {
			wp_send_json_error($result);
		}
	}

	public function ajax_clear_geoip_cache() {
		check_ajax_referer('baskerville_clear_geoip_cache', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville-ai-security')));
		}

		$core = new Baskerville_Core();
		$cleared = $core->fc_clear_geoip_cache();

		wp_send_json_success(array(
			/* translators: %d is the number of cache entries cleared */
			'message' => sprintf(__('Cleared %d GeoIP cache entries', 'baskerville-ai-security'), $cleared),
			'cleared' => $cleared
		));
	}

	private function render_geoip_test_tab() {
		// Get current visitor IP
		$visitor_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));

		// Check if testing a custom IP (via POST)
		$test_ip = '';
		if (isset($_POST['test_ip']) && isset($_POST['_wpnonce'])) {
			if (wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'])), 'baskerville_test_ip')) {
				$test_ip = sanitize_text_field(wp_unslash($_POST['test_ip']));
			}
		}
		$current_ip = !empty($test_ip) && filter_var($test_ip, FILTER_VALIDATE_IP) ? $test_ip : $visitor_ip;
		$is_custom_ip = !empty($test_ip) && $test_ip !== $visitor_ip;

		$results = null;
		$error = null;

		if ($current_ip && filter_var($current_ip, FILTER_VALIDATE_IP)) {
			try {
				$core = new Baskerville_Core();
				$results = $core->test_geoip_sources($current_ip);
			} catch (Exception $e) {
				$error = $e->getMessage();
			} catch (Error $e) {
				$error = $e->getMessage();
			}
		}
		?>

		<div class="geoip-test-container">
			<!-- IP Test Form -->
			<div class="geoip-test-form baskerville-mb-20">
				<h2><?php esc_html_e('Test IP Address', 'baskerville-ai-security'); ?></h2>
				<p class="baskerville-text-muted"><?php esc_html_e('Enter any IP address to test GeoIP detection and blocking status.', 'baskerville-ai-security'); ?></p>
				<form method="post" action="">
					<?php wp_nonce_field('baskerville_test_ip'); ?>
					<input type="text"
							name="test_ip"
							value="<?php echo esc_attr($current_ip); ?>"
							placeholder="<?php esc_attr_e('Enter IP address (IPv4 or IPv6)', 'baskerville-ai-security'); ?>"
					/>
					<button type="submit" class="button button-primary"><?php esc_html_e('Test IP', 'baskerville-ai-security'); ?></button>
					<?php if ($is_custom_ip): ?>
						<a href="?page=baskerville&tab=geoip-test" class="button"><?php esc_html_e('Reset to My IP', 'baskerville-ai-security'); ?></a>
					<?php endif; ?>

					<?php if ($is_custom_ip): ?>
						<p class="baskerville-mt-10">
							<span class="baskerville-badge baskerville-badge-info"><?php esc_html_e('Testing custom IP', 'baskerville-ai-security'); ?></span>
							<?php
							/* translators: %s: visitor's IP address */
							printf(esc_html__('Your actual IP: %s', 'baskerville-ai-security'), '<code>' . esc_html($visitor_ip) . '</code>');
							?>
						</p>
					<?php endif; ?>
				</form>
			</div>

			<?php
			// Get GeoIP ban settings
			$options = get_option('baskerville_settings', array());
			$geoip_mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';
			$blacklist_countries = isset($options['blacklist_countries']) ? $options['blacklist_countries'] : '';
			$whitelist_countries = isset($options['whitelist_countries']) ? $options['whitelist_countries'] : '';
			$core = new Baskerville_Core();
			$detected_country = $current_ip ? $core->get_country_by_ip($current_ip) : null;
			$is_whitelisted = $current_ip ? $core->is_whitelisted_ip($current_ip) : false;

			// Determine if would be blocked
			$would_block = false;
			$block_reason = '';
			if ($current_ip && !$is_whitelisted && $geoip_mode !== 'allow_all' && $detected_country) {
				if ($geoip_mode === 'blacklist' && !empty($blacklist_countries)) {
					$blacklist_arr = array_map('trim', array_map('strtoupper', explode(',', $blacklist_countries)));
					$would_block = in_array($detected_country, $blacklist_arr, true);
					$block_reason = $would_block ? __( 'Country IS in blacklist', 'baskerville-ai-security' ) : __( 'Country NOT in blacklist', 'baskerville-ai-security' );
				} elseif ($geoip_mode === 'whitelist' && !empty($whitelist_countries)) {
					$whitelist_arr = array_map('trim', array_map('strtoupper', explode(',', $whitelist_countries)));
					$would_block = !in_array($detected_country, $whitelist_arr, true);
					$block_reason = $would_block ? __( 'Country NOT in whitelist', 'baskerville-ai-security' ) : __( 'Country in whitelist', 'baskerville-ai-security' );
				}
			}
			?>

			<!-- GeoIP Ban Status Card -->
			<div class="geoip-test-form baskerville-mb-20">
				<h2>🚫 <?php esc_html_e('GeoIP Country Ban Status', 'baskerville-ai-security'); ?></h2>
				<table class="widefat baskerville-mt-15">
					<tr>
						<td class="baskerville-td-label baskerville-td-label-wide"><?php esc_html_e('Your IP Address', 'baskerville-ai-security'); ?></td>
						<td><code><?php echo esc_html($current_ip); ?></code></td>
					</tr>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Detected Country', 'baskerville-ai-security'); ?></td>
						<td>
							<?php if ($detected_country): ?>
								<strong class="baskerville-text-primary baskerville-text-lg"><?php echo esc_html($detected_country); ?></strong>
							<?php else: ?>
								<span class="baskerville-text-danger">❌ <?php esc_html_e('NOT DETECTED - GeoIP not configured', 'baskerville-ai-security'); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('GeoIP Mode', 'baskerville-ai-security'); ?></td>
						<td>
							<strong><?php echo esc_html($geoip_mode); ?></strong>
							<?php if ($geoip_mode === 'allow_all'): ?>
								<span class="baskerville-text-success"> (<?php esc_html_e('All countries allowed', 'baskerville-ai-security'); ?>)</span>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ($geoip_mode === 'blacklist'): ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Block List Countries', 'baskerville-ai-security'); ?></td>
						<td>
							<?php if (!empty($blacklist_countries)): ?>
								<code><?php echo esc_html($blacklist_countries); ?></code>
							<?php else: ?>
								<em class="baskerville-text-muted"><?php esc_html_e('(empty - no countries in block list)', 'baskerville-ai-security'); ?></em>
							<?php endif; ?>
						</td>
					</tr>
					<?php endif; ?>
					<?php if ($geoip_mode === 'whitelist'): ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Allow List Countries', 'baskerville-ai-security'); ?></td>
						<td>
							<?php if (!empty($whitelist_countries)): ?>
								<code><?php echo esc_html($whitelist_countries); ?></code>
							<?php else: ?>
								<em class="baskerville-text-muted"><?php esc_html_e('(empty - all countries blocked)', 'baskerville-ai-security'); ?></em>
							<?php endif; ?>
						</td>
					</tr>
					<?php endif; ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('IP in Allow List?', 'baskerville-ai-security'); ?></td>
						<td>
							<?php if ($is_whitelisted): ?>
								<span class="baskerville-status-yes"><?php esc_html_e( '✓ YES (bypasses all protection)', 'baskerville-ai-security' ); ?></span>
							<?php else: ?>
								<span class="baskerville-text-muted"><?php esc_html_e( 'NO', 'baskerville-ai-security' ); ?></span>
							<?php endif; ?>
						</td>
					</tr>
				</table>

				<!-- Decision Box -->
				<?php
				$decision_class = ($is_whitelisted || !$detected_country || $geoip_mode === 'allow_all' || !$would_block)
					? 'baskerville-decision-box-allowed'
					: 'baskerville-decision-box-blocked';
				?>
				<div class="baskerville-decision-box <?php echo esc_attr($decision_class); ?>">
					<h3 class="baskerville-section-title">
						<?php if ($is_whitelisted): ?>
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville-ai-security'); ?></span>
						<?php elseif (!$detected_country): ?>
							⚠️ <span class="baskerville-text-warning"><?php esc_html_e('ALLOWED (by default)', 'baskerville-ai-security'); ?></span>
						<?php elseif ($geoip_mode === 'allow_all'): ?>
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville-ai-security'); ?></span>
						<?php elseif ($would_block): ?>
							❌ <span class="baskerville-text-danger"><?php esc_html_e('BLOCKED', 'baskerville-ai-security'); ?></span>
						<?php else: ?>
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville-ai-security'); ?></span>
						<?php endif; ?>
					</h3>
					<p class="baskerville-mt-0 baskerville-font-sm">
						<?php if ($is_whitelisted): ?>
							<?php esc_html_e('This IP is in the IP Allow List and bypasses all protection including GeoIP bans.', 'baskerville-ai-security'); ?>
						<?php elseif (!$detected_country): ?>
							<?php esc_html_e('Country not detected. GeoIP database might be missing. Go to "GeoIP Configuration Status" below to check.', 'baskerville-ai-security'); ?>
						<?php elseif ($geoip_mode === 'allow_all'): ?>
							<?php esc_html_e('GeoIP mode is set to "Allow All". Go to Countries tab to enable blocking.', 'baskerville-ai-security'); ?>
						<?php elseif ($would_block): ?>
							<strong><?php esc_html_e('Reason:', 'baskerville-ai-security'); ?></strong> <?php echo esc_html($block_reason); ?><br>
							<?php esc_html_e('This IP would receive 403 Forbidden on the website.', 'baskerville-ai-security'); ?>
						<?php else: ?>
							<strong><?php esc_html_e('Reason:', 'baskerville-ai-security'); ?></strong> <?php echo esc_html($block_reason); ?>
						<?php endif; ?>
					</p>
				</div>
			</div>

			<div class="geoip-test-form">
				<h2><?php esc_html_e('GeoIP Configuration Status', 'baskerville-ai-security'); ?></h2>
				<p><?php esc_html_e('This page shows which GeoIP sources are configured and working for your server.', 'baskerville-ai-security'); ?></p>
			</div>

			<?php if ($error): ?>
				<div class="baskerville-alert baskerville-alert-danger baskerville-alert-xl baskerville-mt-20">
					<h3 class="baskerville-text-danger baskerville-mt-0">❌ <?php esc_html_e('Error', 'baskerville-ai-security'); ?></h3>
					<p><strong><?php esc_html_e('Critical error occurred:', 'baskerville-ai-security'); ?></strong></p>
					<pre class="baskerville-pre baskerville-code-sm"><?php echo esc_html($error); ?></pre>
					<p class="baskerville-mb-0">
						<small><?php esc_html_e('Please report this error to plugin support.', 'baskerville-ai-security'); ?></small>
					</p>
				</div>
			<?php elseif ($results): ?>
				<div class="geoip-info-box">
					<strong><?php esc_html_e('Testing IP:', 'baskerville-ai-security'); ?></strong> <code><?php echo esc_html($current_ip); ?></code>
					<?php if ($is_custom_ip): ?>
						<span class="baskerville-badge baskerville-badge-warning"><?php esc_html_e('Custom IP', 'baskerville-ai-security'); ?></span>
					<?php endif; ?>
					<br><strong><?php esc_html_e('Priority order:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e( 'NGINX GeoIP2 → NGINX GeoIP Legacy → NGINX Custom Header → Cloudflare → MaxMind → Deflect GeoIP', 'baskerville-ai-security' ); ?>
				</div>

				<div class="geoip-results">
					<h2><?php esc_html_e('GeoIP Test Results', 'baskerville-ai-security'); ?></h2>

					<!-- NGINX GeoIP2 -->
					<div class="geoip-source <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_geoip2'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'NGINX GeoIP2', 'baskerville-ai-security' ); ?></div>
						<div class="geoip-source-result <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_geoip2'] ? esc_html($results['nginx_geoip2']) : esc_html__('Not configured', 'baskerville-ai-security'); ?>
						</div>
					</div>

					<!-- NGINX GeoIP Legacy -->
					<div class="geoip-source <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_geoip_legacy'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'NGINX GeoIP (legacy)', 'baskerville-ai-security' ); ?></div>
						<div class="geoip-source-result <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_geoip_legacy'] ? esc_html($results['nginx_geoip_legacy']) : esc_html__('Not configured', 'baskerville-ai-security'); ?>
						</div>
					</div>

					<!-- NGINX Custom Header -->
					<div class="geoip-source <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_custom_header'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'NGINX Custom Header', 'baskerville-ai-security' ); ?></div>
						<div class="geoip-source-result <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_custom_header'] ? esc_html($results['nginx_custom_header']) : esc_html__('Not configured', 'baskerville-ai-security'); ?>
						</div>
					</div>

					<!-- Cloudflare -->
					<div class="geoip-source <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['cloudflare'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'Cloudflare', 'baskerville-ai-security' ); ?></div>
						<div class="geoip-source-result <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['cloudflare'] ? esc_html($results['cloudflare']) : esc_html__('Not available', 'baskerville-ai-security'); ?>
						</div>
					</div>

					<!-- MaxMind -->
					<div class="geoip-source <?php echo $results['maxmind'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['maxmind'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'MaxMind GeoLite2', 'baskerville-ai-security' ); ?> <small class="baskerville-text-muted">(<?php esc_html_e('manual updates', 'baskerville-ai-security'); ?>)</small></div>
						<div class="geoip-source-result <?php echo $results['maxmind'] ? 'available' : 'unavailable'; ?>">
							<?php
							if ($results['maxmind']) {
								echo esc_html($results['maxmind']);
							} else {
								echo esc_html__('Database not found or not configured', 'baskerville-ai-security');
							}
							?>
						</div>
					</div>

					<!-- Deflect GeoIP -->
					<div class="geoip-source <?php echo $results['deflect'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['deflect'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name"><?php esc_html_e( 'Deflect GeoIP', 'baskerville-ai-security' ); ?> <small class="baskerville-text-muted">(<?php esc_html_e('less accurate, auto-updates', 'baskerville-ai-security'); ?>)</small></div>
						<div class="geoip-source-result <?php echo $results['deflect'] ? 'available' : 'unavailable'; ?>">
							<?php
							if ($results['deflect']) {
								echo esc_html($results['deflect']);
							} else {
								echo esc_html__('Database not installed', 'baskerville-ai-security');
							}
							?>
						</div>
					</div>
				</div>

				<!-- MaxMind Debug Information -->
				<?php if (isset($results['maxmind_debug'])): ?>
				<div class="baskerville-debug-box">
					<h3><?php esc_html_e('MaxMind GeoLite2 Database', 'baskerville-ai-security'); ?> <span class="baskerville-badge baskerville-badge-warning"><?php esc_html_e('Manual updates', 'baskerville-ai-security'); ?></span></h3>
					<p class="baskerville-text-muted"><?php esc_html_e('More accurate than Deflect GeoIP but requires manual download and updates. You need to register at MaxMind and upload the database file yourself.', 'baskerville-ai-security'); ?></p>
					<table class="baskerville-debug-table-full">
						<tr>
							<td><?php esc_html_e( 'Expected DB Path:', 'baskerville-ai-security' ); ?></td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['expected_path']); ?></code>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'File Exists:', 'baskerville-ai-security' ); ?></td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['file_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['file_exists'] ? esc_html__( 'YES ✓', 'baskerville-ai-security' ) : esc_html__( 'NO ✗', 'baskerville-ai-security' ); ?>
								</span>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'File Readable:', 'baskerville-ai-security' ); ?></td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['is_readable'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['is_readable'] ? esc_html__( 'YES ✓', 'baskerville-ai-security' ) : esc_html__( 'NO ✗', 'baskerville-ai-security' ); ?>
								</span>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'File Size:', 'baskerville-ai-security' ); ?></td>
							<td>
								<?php
								if ($results['maxmind_debug']['file_size'] > 0) {
									echo number_format($results['maxmind_debug']['file_size'] / 1024 / 1024, 2) . ' MB';
								} else {
									echo '<span class="baskerville-text-danger">' . esc_html__( '0 bytes', 'baskerville-ai-security' ) . '</span>';
								}
								?>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'WP_CONTENT_DIR:', 'baskerville-ai-security' ); ?></td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['wp_content_dir']); ?></code>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Autoload Path:', 'baskerville-ai-security' ); ?></td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['autoload_path']); ?></code>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Autoload Exists:', 'baskerville-ai-security' ); ?></td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['autoload_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['autoload_exists'] ? esc_html__( 'YES ✓', 'baskerville-ai-security' ) : esc_html__( 'NO ✗', 'baskerville-ai-security' ); ?>
								</span>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'GeoIp2 Class Available:', 'baskerville-ai-security' ); ?></td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['class_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['class_exists'] ? esc_html__( 'YES ✓', 'baskerville-ai-security' ) : esc_html__( 'NO ✗', 'baskerville-ai-security' ); ?>
								</span>
							</td>
						</tr>
						<?php if (isset($results['maxmind_debug']['error'])): ?>
						<tr class="baskerville-alert-danger">
							<td><?php esc_html_e( 'Error Message:', 'baskerville-ai-security' ); ?></td>
							<td class="baskerville-text-danger">
								<?php echo esc_html($results['maxmind_debug']['error']); ?>
							</td>
						</tr>
						<?php endif; ?>
					</table>

					<?php
					// Provide specific help based on diagnostics
					if (!$results['maxmind_debug']['file_exists']):
					?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('Database file not found!', 'baskerville-ai-security'); ?></strong><br>
							<?php esc_html_e('Please upload GeoLite2-Country.mmdb to:', 'baskerville-ai-security'); ?><br>
							<code class="baskerville-code-block">
								<?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
							</code>
							<strong><?php esc_html_e('Download from:', 'baskerville-ai-security'); ?></strong>
							<a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank"><?php esc_html_e( 'MaxMind GeoLite2', 'baskerville-ai-security' ); ?></a>
						</div>
					<?php elseif (!$results['maxmind_debug']['is_readable']): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('Database file exists but is not readable!', 'baskerville-ai-security'); ?></strong><br>
							<?php esc_html_e('Check file permissions. Try:', 'baskerville-ai-security'); ?><br>
							<code class="baskerville-code-block">
								chmod 644 <?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
							</code>
						</div>
					<?php elseif (!$results['maxmind_debug']['autoload_exists']): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('MaxMind PHP library not installed!', 'baskerville-ai-security'); ?></strong><br>
							<?php esc_html_e('Click the button below to install automatically (no Composer required):', 'baskerville-ai-security'); ?><br>

							<button id="baskerville-install-maxmind" class="button button-primary baskerville-mt-15">
								<?php esc_html_e('Install MaxMind Library', 'baskerville-ai-security'); ?>
							</button>
							<span id="baskerville-install-status" class="baskerville-ml-10"></span>

							<div class="baskerville-mt-15 baskerville-divider-top">
								<small><strong><?php esc_html_e('Or install manually with Composer:', 'baskerville-ai-security'); ?></strong></small><br>
								<code class="baskerville-code-block baskerville-code-sm">
									cd <?php echo esc_html(BASKERVILLE_PLUGIN_PATH); ?><br>
									composer require geoip2/geoip2
								</code>
							</div>
						</div>

					<?php elseif ($results['maxmind_debug']['file_size'] == 0): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('Database file is empty (0 bytes)!', 'baskerville-ai-security'); ?></strong><br>
							<?php esc_html_e('The file exists but has no data. Please re-download and upload the database.', 'baskerville-ai-security'); ?>
						</div>
					<?php endif; ?>
				</div>
				<?php endif; ?>

				<!-- Deflect GeoIP Debug Information -->
				<?php if (isset($results['deflect_debug'])): ?>
				<div class="baskerville-debug-box">
					<h3><?php esc_html_e('Deflect GeoIP Database', 'baskerville-ai-security'); ?> <span class="baskerville-badge baskerville-badge-success"><?php esc_html_e('Auto-updates', 'baskerville-ai-security'); ?></span></h3>
					<p class="baskerville-text-muted"><?php esc_html_e('Free, open-source GeoIP database. Less accurate than MaxMind but updates automatically every week — no manual action required.', 'baskerville-ai-security'); ?></p>

					<table class="baskerville-debug-table-full">
						<tr>
							<td><?php esc_html_e('Status:', 'baskerville-ai-security'); ?></td>
							<td>
								<span class="<?php echo $results['deflect_debug']['installed'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['deflect_debug']['installed'] ? esc_html__('Installed', 'baskerville-ai-security') . ' ✓' : esc_html__('Not installed', 'baskerville-ai-security') . ' ✗'; ?>
								</span>
							</td>
						</tr>
						<?php if ($results['deflect_debug']['installed']): ?>
						<tr>
							<td><?php esc_html_e('Version:', 'baskerville-ai-security'); ?></td>
							<td><code><?php echo esc_html($results['deflect_debug']['version'] ?? 'N/A'); ?></code></td>
						</tr>
						<tr>
							<td><?php esc_html_e('IPv4 Prefixes:', 'baskerville-ai-security'); ?></td>
							<td><?php echo number_format($results['deflect_debug']['ipv4_count'] ?? 0); ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e('IPv6 Prefixes:', 'baskerville-ai-security'); ?></td>
							<td><?php echo number_format($results['deflect_debug']['ipv6_count'] ?? 0); ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e('Database Path:', 'baskerville-ai-security'); ?></td>
							<td><code><?php echo esc_html($results['deflect_debug']['db_path'] ?? 'N/A'); ?></code></td>
						</tr>
						<?php endif; ?>
						<?php if (isset($results['deflect_debug']['error'])): ?>
						<tr class="baskerville-alert-danger">
							<td><?php esc_html_e('Error:', 'baskerville-ai-security'); ?></td>
							<td class="baskerville-text-danger"><?php echo esc_html($results['deflect_debug']['error']); ?></td>
						</tr>
						<?php endif; ?>
					</table>

					<div class="baskerville-mt-15">
						<button id="baskerville-update-deflect-geoip" class="button button-primary">
							<?php echo $results['deflect_debug']['installed'] ? esc_html__('Check for Updates', 'baskerville-ai-security') : esc_html__('Install Deflect GeoIP Database', 'baskerville-ai-security'); ?>
						</button>
						<span id="baskerville-deflect-status" class="baskerville-ml-10"></span>
					</div>


					<div class="baskerville-alert baskerville-alert-info baskerville-mt-15">
						<strong><?php esc_html_e('About Deflect GeoIP:', 'baskerville-ai-security'); ?></strong><br>
						<?php esc_html_e('This is a free, open-source alternative to MaxMind GeoLite2. The database is compiled from public routing data and updated every Monday.', 'baskerville-ai-security'); ?>
						<br><a href="https://github.com/deflect-ca/deflect-geoip" target="_blank"><?php esc_html_e('Learn more on GitHub', 'baskerville-ai-security'); ?></a>
					</div>
				</div>
				<?php endif; ?>

				<?php
				// Show which source would be used
				$active_source = null;
				$active_country = null;
				if ($results['nginx_geoip2'] && $results['nginx_geoip2'] !== 'N/A (only for current IP)') {
					$active_source = __( 'NGINX GeoIP2', 'baskerville-ai-security' );
					$active_country = $results['nginx_geoip2'];
				} elseif ($results['nginx_geoip_legacy'] && $results['nginx_geoip_legacy'] !== 'N/A (only for current IP)') {
					$active_source = __( 'NGINX GeoIP (legacy)', 'baskerville-ai-security' );
					$active_country = $results['nginx_geoip_legacy'];
				} elseif ($results['nginx_custom_header'] && $results['nginx_custom_header'] !== 'N/A (only for current IP)') {
					$active_source = __( 'NGINX Custom Header', 'baskerville-ai-security' );
					$active_country = $results['nginx_custom_header'];
				} elseif ($results['cloudflare'] && $results['cloudflare'] !== 'N/A (only for current IP)') {
					$active_source = __( 'Cloudflare', 'baskerville-ai-security' );
					$active_country = $results['cloudflare'];
				} elseif ($results['maxmind']) {
					$active_source = __( 'MaxMind GeoLite2', 'baskerville-ai-security' );
					$active_country = $results['maxmind'];
				} elseif ($results['deflect']) {
					$active_source = __( 'Deflect GeoIP', 'baskerville-ai-security' );
					$active_country = $results['deflect'];
				}
				?>

				<div class="geoip-info-box baskerville-alert-success baskerville-mt-20">
					<strong><?php esc_html_e('Active Source:', 'baskerville-ai-security'); ?></strong>
					<?php echo $active_source ? esc_html($active_source) : esc_html__('None available', 'baskerville-ai-security'); ?>
					<?php if ($active_country): ?>
						<br><strong><?php esc_html_e('Country Code:', 'baskerville-ai-security'); ?></strong>
						<span class="baskerville-status-yes baskerville-text-lg"><?php echo esc_html($active_country); ?></span>
					<?php endif; ?>
				</div>

				<!-- Clear GeoIP Cache Button -->
				<div class="baskerville-debug-box">
					<h3><?php esc_html_e('GeoIP Cache Management', 'baskerville-ai-security'); ?></h3>
					<p><?php esc_html_e('If you are using a VPN or your IP location has changed, you may need to clear the GeoIP cache to see the updated country detection.', 'baskerville-ai-security'); ?></p>
					<p><?php esc_html_e('Cache TTL: 7 days', 'baskerville-ai-security'); ?></p>

					<button id="baskerville-clear-geoip-cache" class="button button-secondary baskerville-mt-10">
						🗑️ <?php esc_html_e('Clear GeoIP Cache', 'baskerville-ai-security'); ?>
					</button>
					<span id="baskerville-clear-cache-status" class="baskerville-ml-10"></span>
				</div>

			<?php endif; ?>
		</div>
		<?php
	}

	public function admin_page() {
		// Check user capabilities
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'baskerville-ai-security'));
		}

		// Get current tab
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required for read-only tab navigation parameter
		$current_tab = isset($_GET['tab']) ? sanitize_text_field(wp_unslash($_GET['tab'])) : 'live-feed';

		// Get master switch status
		$options = get_option('baskerville_settings', array());
		$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
		?>
		<div class="wrap">
			<h1><?php echo esc_html(get_admin_page_title()); ?></h1>

			<!-- Master Switch -->
			<div class="baskerville-master-switch <?php echo $master_enabled ? 'baskerville-master-switch-on' : 'baskerville-master-switch-off'; ?>">
				<form method="post" action="options.php" id="master-switch-form">
					<?php settings_fields('baskerville_settings_group'); ?>
					<div class="baskerville-master-switch-header">
						<div>
							<h2 class="baskerville-master-switch-title <?php echo $master_enabled ? 'baskerville-master-switch-title-on' : 'baskerville-master-switch-title-off'; ?>">
								<?php echo $master_enabled ? '🟢' : '🟡'; ?>
								<?php esc_html_e('MASTER SWITCH', 'baskerville-ai-security'); ?>
							</h2>
						</div>
						<div>
							<div class="baskerville-toggle-label">
								<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="0">
								<label class="baskerville-toggle-switch">
									<input type="checkbox"
										   name="baskerville_settings[master_protection_enabled]"
										   value="1"
										   <?php checked($master_enabled, true); ?>
										   onchange="this.form.submit()">
									<span class="baskerville-toggle-slider"></span>
								</label>
								<span class="baskerville-toggle-text">
									<?php echo $master_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
								</span>
							</div>
						</div>
					</div>
				</form>
			</div>

			<!-- Tab Navigation -->
			<?php
			// Get all feature states for tab colors
			$bot_protection_enabled = isset($options['bot_protection_enabled']) ? $options['bot_protection_enabled'] : true;
			$ai_bot_control_enabled = isset($options['ai_bot_control_enabled']) ? $options['ai_bot_control_enabled'] : true;
			$geoip_enabled = isset($options['geoip_enabled']) ? $options['geoip_enabled'] : false;
			$burst_protection_enabled = isset($options['burst_protection_enabled']) ? $options['burst_protection_enabled'] : true;
			$api_rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;
			$turnstile_enabled = isset($options['turnstile_enabled']) ? $options['turnstile_enabled'] : false;
			?>
			<h2 class="nav-tab-wrapper">
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-settings')); ?>"
				   class="nav-tab <?php echo $current_tab === 'live-feed' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Live Feed', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-bot-protection')); ?>"
				   class="nav-tab <?php echo $bot_protection_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'bot-protection' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Bot Control', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-ai-bot-control')); ?>"
				   class="nav-tab <?php echo $ai_bot_control_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'ai-bot-control' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('AI Bot Control', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-country-control')); ?>"
				   class="nav-tab <?php echo $geoip_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'country-control' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Country Control', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-burst-protection')); ?>"
				   class="nav-tab <?php echo $burst_protection_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'burst-protection' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Burst Protection', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-rate-limits')); ?>"
				   class="nav-tab <?php echo $api_rate_limit_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'rate-limits' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Rate Limits', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-turnstile')); ?>"
				   class="nav-tab <?php echo $turnstile_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'turnstile' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Turnstile', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-analytics')); ?>"
				   class="nav-tab <?php echo $current_tab === 'analytics' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Analytics', 'baskerville-ai-security'); ?>
				</a>
				<a href="<?php echo esc_url(admin_url('admin.php?page=baskerville-settings-tab')); ?>"
				   class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Settings', 'baskerville-ai-security'); ?>
				</a>
			</h2>

			<!-- Tab Content -->
			<form method="post" action="options.php">
				<?php
				settings_fields('baskerville_settings_group');

				switch ($current_tab) {
					case 'live-feed':
						?>
						</form>
						<?php
						$this->render_live_feed_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;

					case 'bot-protection':
						?>
						</form>
						<?php
						$bot_enabled = isset($options['bot_protection_enabled']) ? $options['bot_protection_enabled'] : true;
						$allow_verified = !isset($options['allow_verified_crawlers']) || $options['allow_verified_crawlers'];
						?>
						<form method="post" action="options.php">
						<?php
						settings_fields('baskerville_settings_group');
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						?>
						<table class="form-table" role="presentation">
							<tr>
								<td>
									<div class="baskerville-toggle-label">
										<span class="baskerville-toggle-text">
											<?php esc_html_e('Bot Control', 'baskerville-ai-security'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[bot_protection_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[bot_protection_enabled]" value="1" <?php checked($bot_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $bot_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();
						?>
						<table class="form-table" role="presentation">
							<tr>
								<th scope="row"><?php esc_html_e('Verified Crawlers', 'baskerville-ai-security'); ?></th>
								<td>
									<label>
										<input type="hidden" name="baskerville_settings[allow_verified_crawlers]" value="0">
										<input type="checkbox" name="baskerville_settings[allow_verified_crawlers]" value="1" <?php checked($allow_verified, true); ?> />
										<?php esc_html_e('Allow verified crawlers (Google, Bing, Yandex, etc.)', 'baskerville-ai-security'); ?>
									</label>
									<p class="description">
										<?php esc_html_e('Verified crawlers are identified by reverse DNS lookup. When enabled, they bypass bot protection.', 'baskerville-ai-security'); ?>
									</p>
								</td>
							</tr>
							<?php
							$ban_all_bots = isset($options['ban_all_detected_bots']) ? $options['ban_all_detected_bots'] : false;
							$instant_ban_threshold = isset($options['instant_ban_threshold']) ? (int) $options['instant_ban_threshold'] : 85;
							?>
							<tr>
								<th scope="row"><?php esc_html_e('Ban All Detected Bots', 'baskerville-ai-security'); ?></th>
								<td>
									<label>
										<input type="hidden" name="baskerville_settings[ban_all_detected_bots]" value="0">
										<input type="checkbox" name="baskerville_settings[ban_all_detected_bots]" value="1" <?php checked($ban_all_bots, true); ?> />
										<?php esc_html_e('Ban all bots detected (not just "bad bots")', 'baskerville-ai-security'); ?>
									</label>
									<p class="description">
										<?php esc_html_e('When enabled, all visitors classified as "bot" (score ≥70) will be banned after exceeding burst threshold. This includes crawlers like SemrushBot, AhrefsBot, MJ12bot, etc.', 'baskerville-ai-security'); ?>
									</p>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e('Instant Ban Threshold', 'baskerville-ai-security'); ?></th>
								<td>
									<input type="number" name="baskerville_settings[instant_ban_threshold]" value="<?php echo esc_attr($instant_ban_threshold); ?>" min="0" max="100" step="5" class="baskerville-input-sm" />
									<p class="description">
										<?php esc_html_e('Bot score threshold for immediate ban (without waiting for burst). Default: 85.', 'baskerville-ai-security'); ?><br>
										<?php esc_html_e('Visitors with score ≥ this value AND non-browser User-Agent will be banned instantly on first request.', 'baskerville-ai-security'); ?><br><br>
										<strong><?php esc_html_e('Score examples:', 'baskerville-ai-security'); ?></strong><br>
										• <?php esc_html_e('0-30: Normal browser with good headers', 'baskerville-ai-security'); ?><br>
										• <?php esc_html_e('30-60: Suspicious (old browser, missing headers)', 'baskerville-ai-security'); ?><br>
										• <?php esc_html_e('60-80: Likely bot (bot UA, HTTP/1.x, automation signs)', 'baskerville-ai-security'); ?><br>
										• <?php esc_html_e('80-100: Definitely bot (webdriver, known bot UA)', 'baskerville-ai-security'); ?>
									</p>
								</td>
							</tr>
						</table>
						<?php submit_button(); ?>
						</form>
						<form method="post" action="options.php">
						<?php
						break;

					case 'ai-bot-control':
						?>
						</form>
						<?php
						// Enable/Disable checkbox at top
						$ai_enabled = isset($options['ai_bot_control_enabled']) ? $options['ai_bot_control_enabled'] : true;
						?>
						<form method="post" action="options.php">
						<?php
						settings_fields('baskerville_settings_group');
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						?>
						<table class="form-table" role="presentation">
							<tr>
								<td>
									<div class="baskerville-toggle-label">
										<span class="baskerville-toggle-text">
											<?php esc_html_e('AI Bot Control', 'baskerville-ai-security'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[ai_bot_control_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[ai_bot_control_enabled]" value="1" <?php checked($ai_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $ai_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();

						// Display AI bot statistics
						$this->render_ai_bots_tab();

						do_settings_sections('baskerville-ai-bot-control');
						?>
						<input type="hidden" name="baskerville_settings[ai_bot_control_tab]" value="1">
						<?php
						submit_button();
						?>
						</form>

						<form method="post" action="options.php">
						<?php
						break;

					case 'country-control':
						?>
						</form>
						<?php
						$geoip_enabled = isset($options['geoip_enabled']) ? $options['geoip_enabled'] : false;
						$geoip_status = $this->get_active_geoip_source();
						?>

						<!-- GeoIP Source Status Banner -->
						<?php if ($geoip_status['available']): ?>
						<div class="baskerville-alert baskerville-alert-success baskerville-alert-flex baskerville-alert-my-lg">
							<span class="baskerville-banner-icon">&#127760;</span>
							<div>
								<strong><?php esc_html_e('GeoIP Source:', 'baskerville-ai-security'); ?></strong> <?php echo esc_html($geoip_status['source']); ?>
								<?php if (!empty($geoip_status['country'])): ?>
									&mdash; <?php esc_html_e('Your country:', 'baskerville-ai-security'); ?> <strong><?php echo esc_html($geoip_status['country']); ?></strong>
								<?php endif; ?>
								<?php if (!empty($geoip_status['note'])): ?>
									<br><small class="baskerville-text-muted"><?php echo esc_html($geoip_status['note']); ?></small>
								<?php endif; ?>
							</div>
						</div>
						<?php else: ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-flex baskerville-alert-my-lg">
							<span class="baskerville-banner-icon">&#9888;</span>
							<div>
								<strong class="baskerville-text-warning"><?php esc_html_e('No GeoIP source configured!', 'baskerville-ai-security'); ?></strong><br>
								<span class="baskerville-text-warning">
									<?php
									printf(
										/* translators: %s: link to settings tab */
										esc_html__('Country blocking will not work. Go to %s to install MaxMind GeoLite2 database.', 'baskerville-ai-security'),
										'<a href="' . esc_url(admin_url('admin.php?page=baskerville-settings-tab')) . '"><strong>' . esc_html__('Settings tab', 'baskerville-ai-security') . '</strong></a>'
									);
									?>
								</span>
							</div>
						</div>
						<?php endif; ?>

						<form method="post" action="options.php">
						<?php
						settings_fields('baskerville_settings_group');
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						?>
						<table class="form-table" role="presentation">
							<tr>
								<td>
									<div class="baskerville-toggle-label">
										<span class="baskerville-toggle-text">
											<?php esc_html_e('Country Control', 'baskerville-ai-security'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[geoip_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[geoip_enabled]" value="1" <?php checked($geoip_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $geoip_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();
						do_settings_sections('baskerville-country-control');
						submit_button();
						?>
						</form>

						<?php
						// Display country statistics and charts below the form
						$this->render_countries_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;

					case 'burst-protection':
						?>
						</form>
						<?php
						$burst_enabled = isset($options['burst_protection_enabled']) ? $options['burst_protection_enabled'] : true;
						?>
						<form method="post" action="options.php">
						<?php
						settings_fields('baskerville_settings_group');
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						?>
						<table class="form-table" role="presentation">
							<tr>
								<td>
									<div class="baskerville-toggle-label">
										<span class="baskerville-toggle-text">
											<?php esc_html_e('Burst Protection', 'baskerville-ai-security'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[burst_protection_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[burst_protection_enabled]" value="1" <?php checked($burst_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $burst_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();
						?>
						<?php $this->render_burst_protection_content(); ?>
						<?php submit_button(); ?>
						</form>
						<form method="post" action="options.php">
						<?php
						break;

					case 'rate-limits':
						?>
						</form>
						<?php
						$rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;
						$rate_limit_requests = isset($options['api_rate_limit_requests']) ? (int)$options['api_rate_limit_requests'] : 100;
						$rate_limit_window = isset($options['api_rate_limit_window']) ? (int)$options['api_rate_limit_window'] : 60;
						?>
						<form method="post" action="options.php">
						<?php
						settings_fields('baskerville_settings_group');
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						?>
						<table class="form-table" role="presentation">
							<tr>
								<td>
									<div class="baskerville-toggle-label">
										<span class="baskerville-toggle-text">
											<?php esc_html_e('Rate Limits', 'baskerville-ai-security'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[api_rate_limit_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[api_rate_limit_enabled]" value="1" <?php checked($rate_limit_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $rate_limit_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();
						?>

						<div class="baskerville-info-box">
							<h3><?php esc_html_e('How Rate Limiting Works', 'baskerville-ai-security'); ?></h3>
							<p>
								<?php esc_html_e('Rate limiting protects your API endpoints from abuse by limiting the number of requests per IP address within a time window.', 'baskerville-ai-security'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('Protected endpoints:', 'baskerville-ai-security'); ?></strong>
								<?php esc_html_e('REST API (/wp-json/), GraphQL, XML-RPC, and webhook URLs.', 'baskerville-ai-security'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('When limit is exceeded:', 'baskerville-ai-security'); ?></strong>
								<?php esc_html_e('Returns HTTP 429 (Too Many Requests) with Retry-After header.', 'baskerville-ai-security'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('Example:', 'baskerville-ai-security'); ?></strong>
								<?php
								printf(
									/* translators: 1: number of requests, 2: time window in seconds */
									esc_html__('With default settings (100 requests / 60 seconds), an IP making more than 100 API calls per minute will be temporarily blocked.', 'baskerville-ai-security')
								);
								?>
							</p>
						</div>
						<table class="form-table" role="presentation">
							<tr>
								<th scope="row">
									<label for="api_rate_limit_requests">
										<?php esc_html_e('Request Limit', 'baskerville-ai-security'); ?>
									</label>
								</th>
								<td>
									<input type="number"
										   id="api_rate_limit_requests"
										   name="baskerville_settings[api_rate_limit_requests]"
										   value="<?php echo esc_attr($rate_limit_requests); ?>"
										   min="1"
										   max="10000"
										   class="small-text" />
									<?php esc_html_e('requests', 'baskerville-ai-security'); ?>
									<p class="description">
										<?php esc_html_e('Maximum number of requests allowed per IP address.', 'baskerville-ai-security'); ?>
									</p>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="api_rate_limit_window">
										<?php esc_html_e('Time Window', 'baskerville-ai-security'); ?>
									</label>
								</th>
								<td>
									<input type="number"
										   id="api_rate_limit_window"
										   name="baskerville_settings[api_rate_limit_window]"
										   value="<?php echo esc_attr($rate_limit_window); ?>"
										   min="10"
										   max="3600"
										   class="small-text" />
									<?php esc_html_e('seconds', 'baskerville-ai-security'); ?>
									<p class="description">
										<?php esc_html_e('Time window for the rate limit (60 seconds = 1 minute).', 'baskerville-ai-security'); ?>
									</p>
								</td>
							</tr>
						</table>
						<?php submit_button(); ?>
						</form>
						<form method="post" action="options.php">
						<?php
						break;

					case 'turnstile':
						?>
						</form>
						<?php
						$this->render_turnstile_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;

					case 'analytics':
						?>
						</form>
						<?php
						$this->render_analytics_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;

					case 'settings':
						// Preserve master switch state
						$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
						echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
						submit_button();
						do_settings_sections('baskerville-settings');
						submit_button();
						?>
						</form>
						<?php
						// Render GeoIP Testing section
						$this->render_geoip_test_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;

					default:
						?>
						</form>
						<?php
						$this->render_live_feed_tab();
						?>
						<form method="post" action="options.php">
						<?php
						break;
				}
				?>
			</form>
		</div>
		<?php
	}

	/* ===== New Tab Render Methods ===== */

	private function render_live_feed_tab() {
		// Render the existing traffic tab (Live Feed)
		$this->render_traffic_tab();
	}

	private function render_bot_protection_tab() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['bot_protection_enabled']) ? $options['bot_protection_enabled'] : true;
		?>
		<div class="baskerville-section-header <?php echo $enabled ? 'enabled' : ''; ?>">
			<h2>
				🛡️ <?php esc_html_e('Bot Control', 'baskerville-ai-security'); ?>
				<span class="baskerville-section-status <?php echo $enabled ? 'enabled' : 'disabled'; ?>">
					<?php echo $enabled ? '✓ ENABLED' : 'DISABLED'; ?>
				</span>
			</h2>
			<p><?php esc_html_e('Automatic protection from malicious bots, scrapers, and suspicious user agents', 'baskerville-ai-security'); ?></p>
		</div>
		<?php
	}

	private function render_burst_protection_tab() {
		// Header removed - slider at top
	}

	private function render_rate_limits_tab() {
		$options = get_option('baskerville_settings', array());
		$enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;
		?>
		<div class="baskerville-tab-header baskerville-rate-header <?php echo $enabled ? 'baskerville-rate-header-enabled' : 'baskerville-rate-header-disabled'; ?>">
			<h2 class="baskerville-rate-title">
				🚦 <?php esc_html_e('Rate Limits', 'baskerville-ai-security'); ?>
				<span class="baskerville-rate-status <?php echo $enabled ? 'baskerville-rate-status-on' : 'baskerville-rate-status-off'; ?>">
					<?php echo $enabled ? '✓ ENABLED' : 'DISABLED'; ?>
				</span>
			</h2>
			<p class="baskerville-rate-desc">
				<?php esc_html_e('API and endpoint rate limiting', 'baskerville-ai-security'); ?>
			</p>
		</div>

		<!-- Enable/Disable toggle at top -->
		<table class="form-table" role="presentation">
			<tr>
				<td>
					<div class="baskerville-toggle-label">
						<input type="hidden" name="baskerville_settings[api_rate_limit_enabled]" value="0">
						<label class="baskerville-toggle-switch">
							<input type="checkbox" name="baskerville_settings[api_rate_limit_enabled]" value="1" <?php checked($enabled, true); ?> />
							<span class="baskerville-toggle-slider-regular"></span>
						</label>
						<span class="baskerville-toggle-text">
							<?php echo $enabled ? esc_html__('Rate Limits ON', 'baskerville-ai-security') : esc_html__('Rate Limits OFF', 'baskerville-ai-security'); ?>
						</span>
					</div>
				</td>
			</tr>
		</table>
		<?php
	}

	private function render_turnstile_tab() {
		$options = get_option('baskerville_settings', array());
		$turnstile_enabled = isset($options['turnstile_enabled']) ? $options['turnstile_enabled'] : false;
		$site_key = isset($options['turnstile_site_key']) ? $options['turnstile_site_key'] : '';
		$secret_key = isset($options['turnstile_secret_key']) ? $options['turnstile_secret_key'] : '';
		?>
		<form method="post" action="options.php">
			<?php
			settings_fields('baskerville_settings_group');
			// Preserve master switch state
			$master_enabled = !isset($options['master_protection_enabled']) || $options['master_protection_enabled'];
			echo '<input type="hidden" name="baskerville_settings[master_protection_enabled]" value="' . ($master_enabled ? '1' : '0') . '">';
			?>

			<table class="form-table" role="presentation">
				<tr>
					<td>
						<div class="baskerville-toggle-label">
							<span class="baskerville-toggle-text">
								<?php esc_html_e('Cloudflare Turnstile', 'baskerville-ai-security'); ?>
							</span>
							<input type="hidden" name="baskerville_settings[turnstile_enabled]" value="0">
							<label class="baskerville-toggle-switch">
								<input type="checkbox" name="baskerville_settings[turnstile_enabled]" value="1" <?php checked($turnstile_enabled, true); ?> />
								<span class="baskerville-toggle-slider-regular"></span>
							</label>
							<span class="baskerville-toggle-text">
								<?php echo $turnstile_enabled ? esc_html__('ON', 'baskerville-ai-security') : esc_html__('OFF', 'baskerville-ai-security'); ?>
							</span>
						</div>
						<p class="description baskerville-mt-10">
							<?php esc_html_e('When enabled, Turnstile challenge will be shown on sensitive pages:', 'baskerville-ai-security'); ?>
							<strong>wp-login.php</strong>,
							<strong><?php esc_html_e('Registration', 'baskerville-ai-security'); ?></strong>,
							<strong><?php esc_html_e('Comment form', 'baskerville-ai-security'); ?></strong>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>

			<!-- Bot Score Challenge Settings -->
			<div class="baskerville-form-container">
				<h3 class="baskerville-section-title"><?php esc_html_e('Bot Score Challenge', 'baskerville-ai-security'); ?></h3>
				<p class="description">
					<?php esc_html_e('Show Turnstile challenge to visitors with borderline bot scores instead of blocking them outright.', 'baskerville-ai-security'); ?>
				</p>

				<?php
				$challenge_borderline = isset($options['turnstile_challenge_borderline']) ? (bool) $options['turnstile_challenge_borderline'] : false;
				$borderline_min = isset($options['turnstile_borderline_min']) ? (int) $options['turnstile_borderline_min'] : 40;
				$borderline_max = isset($options['turnstile_borderline_max']) ? (int) $options['turnstile_borderline_max'] : 70;
				$is_disabled = !$turnstile_enabled || empty($site_key) || empty($secret_key);
				?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e('Enable', 'baskerville-ai-security'); ?></th>
						<td>
							<label>
								<input type="hidden" name="baskerville_settings[turnstile_challenge_borderline]" value="0">
								<input type="checkbox"
									   name="baskerville_settings[turnstile_challenge_borderline]"
									   value="1"
									   <?php checked($challenge_borderline, true); ?>
									   <?php disabled($is_disabled, true); ?>
								/>
								<?php esc_html_e('Use Turnstile challenge for borderline bot scores', 'baskerville-ai-security'); ?>
							</label>
							<?php if ($is_disabled): ?>
								<p class="description baskerville-text-danger">
									<?php esc_html_e('Enable Turnstile and configure keys above to use this feature.', 'baskerville-ai-security'); ?>
								</p>
							<?php else: ?>
								<p class="description">
									<?php esc_html_e('Instead of blocking visitors with uncertain bot scores, show them a Turnstile challenge. If they pass, they are allowed through.', 'baskerville-ai-security'); ?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label><?php esc_html_e('Score Range', 'baskerville-ai-security'); ?></label>
						</th>
						<td>
							<input type="number"
								   name="baskerville_settings[turnstile_borderline_min]"
								   value="<?php echo esc_attr($borderline_min); ?>"
								   min="0"
								   max="100"
								   step="1"
								   class="baskerville-input-xs"
								   <?php disabled($is_disabled, true); ?>
							/>
							<span class="baskerville-mx-10"><?php esc_html_e('to', 'baskerville-ai-security'); ?></span>
							<input type="number"
								   name="baskerville_settings[turnstile_borderline_max]"
								   value="<?php echo esc_attr($borderline_max); ?>"
								   min="0"
								   max="100"
								   step="1"
								   class="baskerville-input-xs"
								   <?php disabled($is_disabled, true); ?>
							/>
							<p class="description">
								<?php esc_html_e('Bot score range (0-100) that triggers Turnstile challenge.', 'baskerville-ai-security'); ?><br>
								<strong><?php esc_html_e('Recommended:', 'baskerville-ai-security'); ?></strong> 40-70<br>
								<span class="baskerville-text-muted">
									• 0-39: <?php esc_html_e('Likely human (allowed)', 'baskerville-ai-security'); ?><br>
									• 40-70: <?php esc_html_e('Borderline (show Turnstile)', 'baskerville-ai-security'); ?><br>
									• 71-100: <?php esc_html_e('Likely bot (blocked)', 'baskerville-ai-security'); ?>
								</span>
							</p>
						</td>
					</tr>
					<?php
					$under_attack_mode = isset($options['turnstile_under_attack']) ? (bool) $options['turnstile_under_attack'] : false;
					?>
					<tr>
						<th scope="row"><?php esc_html_e('Under Attack Mode', 'baskerville-ai-security'); ?></th>
						<td>
							<label class="<?php echo $under_attack_mode ? 'baskerville-text-danger-bold' : ''; ?>">
								<input type="hidden" name="baskerville_settings[turnstile_under_attack]" value="0">
								<input type="checkbox"
									   name="baskerville_settings[turnstile_under_attack]"
									   value="1"
									   <?php checked($under_attack_mode, true); ?>
									   <?php disabled($is_disabled, true); ?>
								/>
								<?php esc_html_e('Show Turnstile challenge to ALL visitors', 'baskerville-ai-security'); ?>
							</label>
							<?php if ($under_attack_mode): ?>
								<p class="description baskerville-text-danger-bold">
									<span class="dashicons dashicons-warning baskerville-text-danger"></span>
									<?php esc_html_e('ACTIVE: All visitors must pass Turnstile challenge!', 'baskerville-ai-security'); ?>
								</p>
							<?php else: ?>
								<p class="description">
									<?php esc_html_e('Emergency mode for when your site is under attack. When enabled, EVERY visitor (including those classified as human) must pass a Turnstile challenge before accessing the site.', 'baskerville-ai-security'); ?><br><br>
									<strong><?php esc_html_e('Use this when:', 'baskerville-ai-security'); ?></strong><br>
									• <?php esc_html_e('Your site is experiencing a DDoS or bot attack', 'baskerville-ai-security'); ?><br>
									• <?php esc_html_e('You see unusual traffic patterns', 'baskerville-ai-security'); ?><br>
									• <?php esc_html_e('Bots are bypassing normal detection', 'baskerville-ai-security'); ?><br><br>
									<span class="baskerville-text-danger"><?php esc_html_e('Warning: This will add friction for real users. Disable when attack subsides.', 'baskerville-ai-security'); ?></span>
								</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>
			</div>

			<!-- Cloudflare Turnstile Configuration (API Keys) -->
			<div class="baskerville-form-container">
				<h3 class="baskerville-section-title"><?php esc_html_e('Cloudflare Turnstile Configuration', 'baskerville-ai-security'); ?></h3>
				<p class="description">
					<?php
					printf(
						/* translators: %s: link to Cloudflare dashboard */
						esc_html__('Get your Site Key and Secret Key from the %s.', 'baskerville-ai-security'),
						'<a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank">' . esc_html__( 'Cloudflare Dashboard', 'baskerville-ai-security' ) . '</a>'
					);
					?>
				</p>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="turnstile_site_key"><?php esc_html_e('Site Key', 'baskerville-ai-security'); ?></label>
						</th>
						<td>
							<input type="text"
								   id="turnstile_site_key"
								   name="baskerville_settings[turnstile_site_key]"
								   value="<?php echo esc_attr($site_key); ?>"
								   class="regular-text"
								   placeholder="0x4AAAAAAA..."
							/>
							<p class="description"><?php esc_html_e('The public site key for your Turnstile widget.', 'baskerville-ai-security'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="turnstile_secret_key"><?php esc_html_e('Secret Key', 'baskerville-ai-security'); ?></label>
						</th>
						<td>
							<input type="password"
								   id="turnstile_secret_key"
								   name="baskerville_settings[turnstile_secret_key]"
								   value="<?php echo esc_attr($secret_key); ?>"
								   class="regular-text"
								   placeholder="0x4AAAAAAA..."
							/>
							<p class="description"><?php esc_html_e('The secret key for server-side verification. Keep this private!', 'baskerville-ai-security'); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<?php submit_button(); ?>
		</form>

		<!-- Turnstile Widget Test -->
		<div class="baskerville-form-container">
			<h3 class="baskerville-section-title"><?php esc_html_e('Widget Test', 'baskerville-ai-security'); ?></h3>

			<?php if (empty($site_key)): ?>
				<div class="baskerville-warning-box">
					<strong><?php esc_html_e('Site Key not configured', 'baskerville-ai-security'); ?></strong><br>
					<?php esc_html_e('Enter your Turnstile Site Key above and save to test the widget.', 'baskerville-ai-security'); ?>
				</div>
			<?php else: ?>
				<p><?php esc_html_e('The Turnstile widget should appear below if configured correctly:', 'baskerville-ai-security'); ?></p>

				<div id="turnstile-test-container" class="baskerville-test-container">
					<div class="cf-turnstile"
						 data-sitekey="<?php echo esc_attr($site_key); ?>"
						 data-callback="onTurnstileSuccess"
						 data-error-callback="onTurnstileError"
						 data-theme="light">
					</div>
				</div>

				<div id="turnstile-status" class="baskerville-test-status"></div>

				<?php
				wp_enqueue_script( 'cloudflare-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', array(), '1.0', false ); // phpcs:ignore PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- Cloudflare Turnstile API must be loaded from Cloudflare servers

				$turnstile_js = 'function onTurnstileSuccess(token) {'
					. 'var statusDiv = document.getElementById("turnstile-status");'
					. 'statusDiv.className = "baskerville-test-status success";'
					. 'statusDiv.innerHTML = "<strong class=\"baskerville-test-success-text\">" + baskervilleAdmin.i18n.turnstileWorking + "</strong><br><small>" + baskervilleAdmin.i18n.tokenReceived + " " + token.substring(0, 20) + "...</small>";'
					. '}'
					. 'function onTurnstileError(error) {'
					. 'var statusDiv = document.getElementById("turnstile-status");'
					. 'statusDiv.className = "baskerville-test-status error";'
					. 'statusDiv.innerHTML = "<strong class=\"baskerville-test-error-text\">" + baskervilleAdmin.i18n.turnstileError + "</strong> " + error;'
					. '}';
				wp_add_inline_script('baskerville-admin', $turnstile_js, 'before');
				?>
			<?php endif; ?>
		</div>
		<?php
	}

	private function render_analytics_tab() {
		// Get selected period from URL, default to 1day
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Nonce verification not required for read-only period filter parameter
		$period = isset($_GET['period']) ? sanitize_text_field(wp_unslash($_GET['period'])) : '1day';
		$valid_periods = array('12h', '1day', '3days', '7days');
		if (!in_array($period, $valid_periods)) {
			$period = '1day';
		}

		$hours_map = array(
			'12h' => 12,
			'1day' => 24,
			'3days' => 72,
			'7days' => 168,
		);
		$hours = $hours_map[$period];

		// Build URLs for period buttons
		$base_url = admin_url('admin.php?page=baskerville-analytics');
		?>

		<h2 class="baskerville-section-heading">
			<span class="dashicons dashicons-chart-area" ></span>
			<?php esc_html_e('Traffic Analytics', 'baskerville-ai-security'); ?>
		</h2>

		<!-- Period Selection Buttons -->
		<div class="period-buttons">
			<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
			   class="button <?php echo $period === '12h' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('12h', 'baskerville-ai-security'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
			   class="button <?php echo $period === '1day' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('1 day', 'baskerville-ai-security'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
			   class="button <?php echo $period === '3days' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('3 days', 'baskerville-ai-security'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
			   class="button <?php echo $period === '7days' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('7 days', 'baskerville-ai-security'); ?>
			</a>
		</div>

		<?php
		// Try to get timeseries data with error handling
		try {
			$timeseries = $this->get_timeseries_data($hours);
			$turnstile_data = $this->get_turnstile_timeseries_data($hours);
			$key_metrics = $this->get_key_metrics($hours);
			?>

			<!-- Key Metrics -->
			<div class="baskerville-key-metrics">
				<!-- Block Rate -->
				<div class="baskerville-metric-card">
					<div class="baskerville-metric-header">
						<span class="baskerville-metric-label"><?php esc_html_e('Block Rate', 'baskerville-ai-security'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-red"><?php echo esc_html($key_metrics['block_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-red" style="width: <?php echo esc_attr(min(100, $key_metrics['block_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: blocked IPs count, %2$s: total IPs count */
							esc_html__('%1$s blocked / %2$s total IPs', 'baskerville-ai-security'),
							'<strong>' . number_format($key_metrics['blocked_ips']) . '</strong>',
							number_format($key_metrics['total_ips'])
						); ?>
					</div>
				</div>

				<!-- Challenge Rate -->
				<div class="baskerville-metric-card">
					<div class="baskerville-metric-header">
						<span class="baskerville-metric-label"><?php esc_html_e('Challenge Rate', 'baskerville-ai-security'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-amber"><?php echo esc_html($key_metrics['challenge_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-amber" style="width: <?php echo esc_attr(min(100, $key_metrics['challenge_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: challenged IPs count, %2$s: total IPs count */
							esc_html__('%1$s challenged / %2$s total IPs', 'baskerville-ai-security'),
							'<strong>' . number_format($key_metrics['challenged_ips']) . '</strong>',
							number_format($key_metrics['total_ips'])
						); ?>
					</div>
				</div>

				<!-- Passed Challenge Rate -->
				<div class="baskerville-metric-card">
					<div class="baskerville-metric-header">
						<span class="baskerville-metric-label"><?php esc_html_e('Passed Challenge', 'baskerville-ai-security'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-green"><?php echo esc_html($key_metrics['pass_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-green" style="width: <?php echo esc_attr(min(100, $key_metrics['pass_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: passed IPs count, %2$s: challenged IPs count */
							esc_html__('%1$s passed / %2$s challenged IPs', 'baskerville-ai-security'),
							'<strong>' . number_format($key_metrics['passed_ips']) . '</strong>',
							number_format($key_metrics['challenged_ips'])
						); ?>
					</div>
				</div>
			</div>

			<div class="baskerville-charts-container">
				<div class="baskerville-chart-card">
					<canvas id="baskervilleHumAutoBar"></canvas>
				</div>
				<div class="baskerville-chart-card">
					<canvas id="baskervilleHumAutoPie"></canvas>
				</div>
			</div>

			<!-- Bot Types Charts -->
			<div class="baskerville-charts-container">
				<div class="baskerville-chart-card">
					<canvas id="baskervilleBotTypesBar"></canvas>
				</div>
				<div class="baskerville-chart-card">
					<canvas id="baskervilleBotTypesPie"></canvas>
				</div>
			</div>

			<!-- Turnstile Precision Charts -->
			<div class="baskerville-charts-container">
				<div class="baskerville-chart-card">
					<canvas id="baskervilleTurnstileBar"></canvas>
				</div>
				<div class="baskerville-chart-card baskerville-chart-card-centered">
					<h3 class="baskerville-precision-title"><?php esc_html_e('Total Precision', 'baskerville-ai-security'); ?></h3>
					<div id="turnstilePrecisionValue" class="baskerville-precision-value"></div>
					<p class="baskerville-precision-subtitle"><?php esc_html_e('% of challenges failed (bots caught)', 'baskerville-ai-security'); ?></p>
					<div class="baskerville-precision-stats">
						<div id="turnstileStats"></div>
					</div>
				</div>
			</div>

			<?php if (is_array($timeseries)):
				wp_add_inline_script('baskerville-admin', 'window.baskervilleAnalyticsData = ' . wp_json_encode(array(
					'timeseries' => $timeseries,
					'turnstile'  => $turnstile_data,
					'hours'      => absint($hours),
				)) . ';', 'before');
			endif; ?>
	<?php
		} catch (Exception $e) {
			/* translators: %s is the error message */
		echo '<div class="notice notice-error"><p>' . sprintf(esc_html__('Charts Error: %s', 'baskerville-ai-security'), esc_html($e->getMessage())) . '</p></div>';
		}
		?>

		<!-- IP Troubleshooting Section -->
		<div class="baskerville-ip-lookup">
			<h2 class="baskerville-ip-lookup-title">
				<span class="dashicons dashicons-search baskerville-icon-lg"></span>
				<?php esc_html_e('IP Troubleshooting', 'baskerville-ai-security'); ?>
			</h2>
			<p class="baskerville-text-muted baskerville-mb-20">
				<?php esc_html_e('Enter an IP address to see its history: bans, block reasons, classifications, and more.', 'baskerville-ai-security'); ?>
			</p>

			<div class="baskerville-ip-lookup-form">
				<input type="text" id="baskerville-ip-lookup" placeholder="<?php esc_attr_e('Enter IP address (e.g., 192.168.1.1)', 'baskerville-ai-security'); ?>"
					   class="baskerville-ip-input">
				<button type="button" id="baskerville-ip-lookup-btn" class="button button-primary baskerville-btn-padded">
					<?php esc_html_e('Search', 'baskerville-ai-security'); ?>
				</button>
			</div>

			<div id="baskerville-ip-results" class="baskerville-hidden">
				<!-- Results will be inserted here -->
			</div>
		</div>

		<?php
	}

	/* ===== IP Whitelist Tab ===== */
	private function render_ip_whitelist_tab() {
		$whitelist = get_option('baskerville_ip_whitelist', '');
		$current_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
		$ips_array = array_filter(preg_split('~[\s,]+~', $whitelist));

		// Handle form submission
		if (isset($_POST['baskerville_save_whitelist']) && check_admin_referer('baskerville_whitelist_save', 'baskerville_whitelist_nonce')) {
			$new_whitelist = isset($_POST['baskerville_ip_whitelist']) ? sanitize_textarea_field(wp_unslash($_POST['baskerville_ip_whitelist'])) : '';
			update_option('baskerville_ip_whitelist', $new_whitelist);
			echo '<div class="notice notice-success"><p>' . esc_html__('IP Allow List saved successfully!', 'baskerville-ai-security') . '</p></div>';
			$whitelist = $new_whitelist;
			$ips_array = array_filter(preg_split('~[\s,]+~', $whitelist));
		}

		// Handle quick add current IP
		if (isset($_POST['baskerville_quick_add_ip']) && check_admin_referer('baskerville_whitelist_quick_add', 'baskerville_whitelist_quick_nonce')) {
			$current_ips = array_filter(preg_split('~[\s,]+~', $whitelist));
			if (!in_array($current_ip, $current_ips, true)) {
				$current_ips[] = $current_ip;
				$new_whitelist = implode("\n", $current_ips);
				update_option('baskerville_ip_whitelist', $new_whitelist);
				/* translators: %s is the IP address added to allow list */
				echo '<div class="notice notice-success"><p>' . sprintf(esc_html__('Added %s to Allow List!', 'baskerville-ai-security'), esc_html($current_ip)) . '</p></div>';
				$whitelist = $new_whitelist;
				$ips_array = $current_ips;
			} else {
				/* translators: %s is the IP address already in allow list */
				echo '<div class="notice notice-info"><p>' . sprintf(esc_html__('%s is already in the Allow List.', 'baskerville-ai-security'), esc_html($current_ip)) . '</p></div>';
			}
		}
		?>
		<div class="baskerville-whitelist-tab">
			<h2><?php esc_html_e('IP Allow List', 'baskerville-ai-security'); ?></h2>

			<div class="card baskerville-card-800">
				<p><?php esc_html_e('IP addresses in the Allow List bypass all firewall checks and will never be blocked by Baskerville.', 'baskerville-ai-security'); ?></p>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
					<strong><?php esc_html_e('Your Current IP:', 'baskerville-ai-security'); ?></strong>
					<code class="baskerville-code"><?php echo esc_html($current_ip); ?></code>

					<?php if (!in_array($current_ip, $ips_array, true) && $current_ip !== 'unknown'): ?>
						<form method="post" class="baskerville-inline-form">
							<?php wp_nonce_field('baskerville_whitelist_quick_add', 'baskerville_whitelist_quick_nonce'); ?>
							<button type="submit" name="baskerville_quick_add_ip" class="button button-secondary baskerville-valign-middle">
								➕ <?php esc_html_e('Add My IP', 'baskerville-ai-security'); ?>
							</button>
						</form>
					<?php else: ?>
						<span class="baskerville-text-success baskerville-ml-10">✅ <?php esc_html_e('Already in Allow List', 'baskerville-ai-security'); ?></span>
					<?php endif; ?>
				</div>

				<form method="post">
					<?php wp_nonce_field('baskerville_whitelist_save', 'baskerville_whitelist_nonce'); ?>

					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="baskerville_ip_whitelist"><?php esc_html_e('Allowed IPs', 'baskerville-ai-security'); ?></label>
							</th>
							<td>
								<textarea
									name="baskerville_ip_whitelist"
									id="baskerville_ip_whitelist"
									rows="10"
									class="large-text code baskerville-font-mono"
								><?php echo esc_textarea($whitelist); ?></textarea>

								<p class="description">
									<?php esc_html_e('Enter one IP address per line. You can also separate IPs with commas or spaces.', 'baskerville-ai-security'); ?><br>
									<strong><?php esc_html_e('Supported formats:', 'baskerville-ai-security'); ?></strong><br>
									• IPv4: <code>192.168.1.1</code><br>
									• IPv6: <code>2001:0db8:85a3::8a2e:0370:7334</code><br>
									• Multiple per line: <code>1.2.3.4, 5.6.7.8</code>
								</p>
							</td>
						</tr>
					</table>

					<?php submit_button(__('Save Allow List', 'baskerville-ai-security'), 'primary', 'baskerville_save_whitelist'); ?>
				</form>
			</div>

			<?php if (!empty($ips_array)): ?>
			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('IPs in Allow List', 'baskerville-ai-security'); ?> (<?php echo count($ips_array); ?>)</h3>
				<table class="widefat striped baskerville-mt-10">
					<thead>
						<tr>
							<th><?php esc_html_e('IP Address', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Status', 'baskerville-ai-security'); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($ips_array as $ip): ?>
						<tr>
							<td>
								<code class="baskerville-text-xs"><?php echo esc_html($ip); ?></code>
								<?php if ($ip === $current_ip): ?>
									<span class="baskerville-text-primary-bold"> (<?php esc_html_e('Your IP', 'baskerville-ai-security'); ?>)</span>
								<?php endif; ?>
							</td>
							<td>
								<?php if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)): ?>
									<span class="baskerville-color-success">✓ <?php esc_html_e('Valid IPv4', 'baskerville-ai-security'); ?></span>
								<?php elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)): ?>
									<span class="baskerville-color-success">✓ <?php esc_html_e('Valid IPv6', 'baskerville-ai-security'); ?></span>
								<?php else: ?>
									<span class="baskerville-desc-danger">✗ <?php esc_html_e('Invalid IP', 'baskerville-ai-security'); ?></span>
								<?php endif; ?>
							</td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php endif; ?>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Use Cases', 'baskerville-ai-security'); ?></h3>
				<ul class="baskerville-list-spaced">
					<li><strong><?php esc_html_e('Load Testing:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e('Add your server IP to run Apache Bench or similar tools', 'baskerville-ai-security'); ?></li>
					<li><strong><?php esc_html_e('Office Network:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e('Add your company IP to ensure team members never get blocked', 'baskerville-ai-security'); ?></li>
					<li><strong><?php esc_html_e('Development:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e('Add localhost (127.0.0.1) if testing locally', 'baskerville-ai-security'); ?></li>
					<li><strong><?php esc_html_e('Monitoring Services:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e('Add uptime monitors or site crawlers', 'baskerville-ai-security'); ?></li>
					<li><strong><?php esc_html_e('API Clients:', 'baskerville-ai-security'); ?></strong> <?php esc_html_e('Add IPs of your API consumers', 'baskerville-ai-security'); ?></li>
				</ul>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-sm baskerville-alert-mt">
					<strong>💡 <?php esc_html_e('Tip:', 'baskerville-ai-security'); ?></strong>
					<?php esc_html_e('IPs in the Allow List completely bypass the firewall. For better security, consider using GeoIP Allow List or verified crawler detection instead when possible.', 'baskerville-ai-security'); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/* ===== Performance Tab ===== */
	private function render_performance_tab() {
		?>
		<div class="baskerville-performance-tab">
			<h2><?php esc_html_e('Performance Benchmarks', 'baskerville-ai-security'); ?></h2>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Internal Benchmarks', 'baskerville-ai-security'); ?></h3>
				<p><?php esc_html_e('Run internal performance tests to measure the overhead of various Baskerville operations.', 'baskerville-ai-security'); ?></p>

				<table class="widefat baskerville-mb-15">
					<thead>
						<tr>
							<th><?php esc_html_e('Test', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Description', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Action', 'baskerville-ai-security'); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><strong><?php esc_html_e('GeoIP Lookup', 'baskerville-ai-security'); ?></strong></td>
							<td><?php esc_html_e('Measure time to perform 100 GeoIP lookups', 'baskerville-ai-security'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="geoip">
									<?php esc_html_e('Run Test', 'baskerville-ai-security'); ?>
								</button>
								<span class="benchmark-result" data-test="geoip"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('AI/UA Classification', 'baskerville-ai-security'); ?></strong></td>
							<td><?php esc_html_e('Measure time to classify 100 user agents', 'baskerville-ai-security'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="ai-ua">
									<?php esc_html_e('Run Test', 'baskerville-ai-security'); ?>
								</button>
								<span class="benchmark-result" data-test="ai-ua"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Cache Operations', 'baskerville-ai-security'); ?></strong></td>
							<td><?php esc_html_e('Measure cache set/get performance (APCu: 1000 ops, File: 100 ops)', 'baskerville-ai-security'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="cache">
									<?php esc_html_e('Run Test', 'baskerville-ai-security'); ?>
								</button>
								<span class="benchmark-result" data-test="cache"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Full Firewall Check', 'baskerville-ai-security'); ?></strong></td>
							<td><?php esc_html_e('Simulate 100 complete firewall checks', 'baskerville-ai-security'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="firewall">
									<?php esc_html_e('Run Test', 'baskerville-ai-security'); ?>
								</button>
								<span class="benchmark-result" data-test="firewall"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Run All Tests', 'baskerville-ai-security'); ?></strong></td>
							<td><?php esc_html_e('Execute all benchmarks sequentially', 'baskerville-ai-security'); ?></td>
							<td>
								<button type="button" class="button button-primary benchmark-btn" data-test="all">
									<?php esc_html_e('Run All', 'baskerville-ai-security'); ?>
								</button>
								<span class="benchmark-result" data-test="all"></span>
							</td>
						</tr>
					</tbody>
				</table>
			</div>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('External Load Testing', 'baskerville-ai-security'); ?></h3>

				<h4><?php esc_html_e('Method 1: File Logging Mode (Recommended)', 'baskerville-ai-security'); ?> ✅</h4>
				<p><?php esc_html_e('Test with firewall ACTIVE but using fast file logging:', 'baskerville-ai-security'); ?></p>
				<ol class="baskerville-list-spaced">
					<li><?php esc_html_e('Go to Settings tab → Select "File Logging" mode', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Run your tests - firewall will process requests normally', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Deactivate plugin and test again to compare', 'baskerville-ai-security'); ?></li>
				</ol>
				<p class="baskerville-color-info"><strong><?php esc_html_e('Expected overhead: ~50-70ms (5%)', 'baskerville-ai-security'); ?></strong></p>

				<h4 class="baskerville-mt-20"><?php esc_html_e('Method 2: Add Your IP to Allow List', 'baskerville-ai-security'); ?></h4>
				<p><?php esc_html_e('Test with firewall BYPASSED (shows minimum overhead):', 'baskerville-ai-security'); ?></p>
				<p><?php esc_html_e('Go to IP Allow List tab → Click "Add My IP" button → Run your tests', 'baskerville-ai-security'); ?></p>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
					<strong><?php esc_html_e('Your Current IP:', 'baskerville-ai-security'); ?></strong>
					<code class="baskerville-code">
						<?php
						echo esc_html(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown')));
						?>
					</code>
				</div>
				<p class="baskerville-color-success"><strong><?php esc_html_e('Expected overhead: ~0-5ms (0%)', 'baskerville-ai-security'); ?></strong></p>

				<h4 class="baskerville-mt-20"><?php esc_html_e('Testing Commands', 'baskerville-ai-security'); ?></h4>
				<pre class="baskerville-pre"># Test WITH plugin (10 samples with pauses)
echo "=== WITH BASKERVILLE ==="
for i in {1..10}; do
  ab -n 1 -c 1 <?php echo esc_url(home_url('/')); ?> 2>&1 | grep "Time per request:" | head -1
  sleep 4
done

# Deactivate plugin in WordPress Admin → Plugins

# Test WITHOUT plugin
echo "=== WITHOUT BASKERVILLE ==="
for i in {1..10}; do
  ab -n 1 -c 1 <?php echo esc_url(home_url('/')); ?> 2>&1 | grep "Time per request:" | head -1
  sleep 4
done

# Compare average times to calculate overhead</pre>

				<h4 class="baskerville-mt-20"><?php esc_html_e('Expected Performance by Mode', 'baskerville-ai-security'); ?></h4>
				<table class="widefat baskerville-mt-10">
					<thead>
						<tr>
							<th><?php esc_html_e('Logging Mode', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Overhead', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Analytics', 'baskerville-ai-security'); ?></th>
							<th><?php esc_html_e('Best For', 'baskerville-ai-security'); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><strong><?php esc_html_e('File Logging', 'baskerville-ai-security'); ?></strong></td>
							<td class="baskerville-color-success">~50-70ms (5%)</td>
							<td>✅ <?php esc_html_e('Full (5min delay)', 'baskerville-ai-security'); ?></td>
							<td><?php esc_html_e('Production', 'baskerville-ai-security'); ?> ✅</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Disabled', 'baskerville-ai-security'); ?></strong></td>
							<td class="baskerville-color-success">~0ms (0%)</td>
							<td>❌ <?php esc_html_e('None', 'baskerville-ai-security'); ?></td>
							<td><?php esc_html_e('Testing/Dev', 'baskerville-ai-security'); ?></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Database', 'baskerville-ai-security'); ?></strong></td>
							<td class="baskerville-color-warning">~500ms (36%)</td>
							<td>✅ <?php esc_html_e('Instant', 'baskerville-ai-security'); ?></td>
							<td><?php esc_html_e('VPS only', 'baskerville-ai-security'); ?> ⚠️</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('IP in Allow List', 'baskerville-ai-security'); ?></strong></td>
							<td class="baskerville-color-success">~0-5ms (0%)</td>
							<td>✅ <?php esc_html_e('Partial', 'baskerville-ai-security'); ?></td>
							<td><?php esc_html_e('Load testing', 'baskerville-ai-security'); ?></td>
						</tr>
					</tbody>
				</table>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-sm baskerville-alert-mt">
					<strong>💡 <?php esc_html_e('Recommendation:', 'baskerville-ai-security'); ?></strong>
					<?php
				printf(
					/* translators: %1$s: opening strong tag, %2$s: closing strong tag */
					esc_html__( 'Use %1$sFile Logging%2$s mode (default) for production. It provides full analytics with minimal overhead (~5%%), perfect for shared hosting.', 'baskerville-ai-security' ),
					'<strong>',
					'</strong>'
				);
				?>
				</div>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm baskerville-alert-mt">
					<strong>⚠️ <?php esc_html_e('Note:', 'baskerville-ai-security'); ?></strong>
					<?php esc_html_e('Absolute response times vary by server, but overhead percentage is consistent. Focus on the % difference, not absolute milliseconds.', 'baskerville-ai-security'); ?>
				</div>
			</div>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Performance Tips', 'baskerville-ai-security'); ?></h3>
				<ul class="baskerville-list-spaced">
					<li><?php esc_html_e('Enable APCu for faster caching (file-based cache is slower)', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Use NGINX GeoIP2 module for fastest country detection', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Allow verified crawlers to reduce unnecessary checks', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('The firewall only runs on public HTML pages (not wp-admin, REST API, or AJAX)', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Database writes are batched and use prepared statements', 'baskerville-ai-security'); ?></li>
				</ul>
			</div>
		</div>

		<?php
	}

	/* ===== API Tab ===== */
	private function render_api_tab() {
		$options = get_option('baskerville_settings', array());
		$rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;
		$rate_limit_requests = isset($options['api_rate_limit_requests']) ? (int)$options['api_rate_limit_requests'] : 100;
		$rate_limit_window = isset($options['api_rate_limit_window']) ? (int)$options['api_rate_limit_window'] : 60;
		?>
		<div class="baskerville-api-tab">
			<h2><?php esc_html_e('API Protection Settings', 'baskerville-ai-security'); ?></h2>

			<!-- How API Detection Works -->
			<div class="card baskerville-card-1000">
				<h3><?php esc_html_e('How API Auto-Detection Works', 'baskerville-ai-security'); ?></h3>

				<p><?php esc_html_e('Baskerville automatically detects API requests and applies special protection rules. API requests BYPASS the firewall (no 403 bans, no burst protection) and only use rate limiting.', 'baskerville-ai-security'); ?></p>

				<h4><?php esc_html_e('Detection Methods:', 'baskerville-ai-security'); ?></h4>

				<div class="baskerville-card">
					<strong>1. <?php esc_html_e('Content-Type Headers:', 'baskerville-ai-security'); ?></strong>
					<p class="baskerville-api-desc">
						<code>application/json</code>, <code>application/xml</code>, <code>application/graphql</code>,
						<code>application/ld+json</code>, <code>multipart/form-data</code>
					</p>
				</div>

				<div class="baskerville-card">
					<strong>2. <?php esc_html_e('URL Patterns:', 'baskerville-ai-security'); ?></strong>
					<p class="baskerville-api-desc">
						<code>/api/</code>, <code>/v1/</code>, <code>/v2/</code>, <code>/v3/</code>,
						<code>/rest/</code>, <code>/graphql/</code>, <code>/wp-json/</code>,
						<code>/webhook/</code>, <code>/payment/</code>, <code>/checkout/</code>,
						<code>/auth/</code>, <code>/oauth/</code>, <code>/token/</code>
					</p>
				</div>

				<div class="baskerville-card">
					<strong>3. <?php esc_html_e('Accept Headers:', 'baskerville-ai-security'); ?></strong>
					<p class="baskerville-api-desc">
						<?php esc_html_e('Requests with Accept header requesting JSON or XML format', 'baskerville-ai-security'); ?>
					</p>
				</div>

				<div class="baskerville-alert baskerville-alert-success baskerville-alert-lg">
					<strong>✓ <?php esc_html_e('What happens to API requests:', 'baskerville-ai-security'); ?></strong>
					<ul class="baskerville-list-indent">
						<li><?php esc_html_e('Bypass all firewall rules (GeoIP, burst protection, bot detection)', 'baskerville-ai-security'); ?></li>
						<li><?php esc_html_e('Never receive 403 Forbidden responses', 'baskerville-ai-security'); ?></li>
						<li><?php esc_html_e('Only subject to rate limiting (429 Too Many Requests)', 'baskerville-ai-security'); ?></li>
						<li><?php esc_html_e('IPs in Allow List bypass rate limiting completely', 'baskerville-ai-security'); ?></li>
					</ul>
				</div>
			</div>

			<!-- Rate Limiting Settings -->
			<div class="card baskerville-card-1000">
				<h3><?php esc_html_e('API Rate Limiting', 'baskerville-ai-security'); ?></h3>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg">
					<strong><?php esc_html_e('How Rate Limiting Works:', 'baskerville-ai-security'); ?></strong>
					<p>
						<?php esc_html_e('Rate limiting counts requests per IP address in a sliding time window. When the limit is exceeded, API requests receive HTTP 429 (Too Many Requests) with a Retry-After header.', 'baskerville-ai-security'); ?>
					</p>
					<p>
						<strong><?php esc_html_e('Example:', 'baskerville-ai-security'); ?></strong>
						<?php esc_html_e('100 requests / 60 seconds means each IP can make maximum 100 API requests per minute. The 101st request returns 429 error.', 'baskerville-ai-security'); ?>
					</p>
				</div>

				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="api_rate_limit_enabled">
								<?php esc_html_e('Enable Rate Limiting', 'baskerville-ai-security'); ?>
							</label>
						</th>
						<td>
							<label>
								<input type="checkbox"
									   id="api_rate_limit_enabled"
									   name="baskerville_settings[api_rate_limit_enabled]"
									   value="1"
									   <?php checked($rate_limit_enabled, true); ?> />
								<?php esc_html_e('Enable rate limiting for REST API endpoints', 'baskerville-ai-security'); ?>
							</label>
							<p class="description">
								<?php esc_html_e('When enabled, API requests exceeding the limit will receive a 429 Too Many Requests response.', 'baskerville-ai-security'); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="api_rate_limit_requests">
								<?php esc_html_e('Request Limit', 'baskerville-ai-security'); ?>
							</label>
						</th>
						<td>
							<input type="number"
								   id="api_rate_limit_requests"
								   name="baskerville_settings[api_rate_limit_requests]"
								   value="<?php echo esc_attr($rate_limit_requests); ?>"
								   min="1"
								   max="10000"
								   class="small-text" />
							<?php esc_html_e('requests', 'baskerville-ai-security'); ?>
							<p class="description">
								<?php esc_html_e('Maximum number of requests allowed per IP address.', 'baskerville-ai-security'); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="api_rate_limit_window">
								<?php esc_html_e('Time Window', 'baskerville-ai-security'); ?>
							</label>
						</th>
						<td>
							<input type="number"
								   id="api_rate_limit_window"
								   name="baskerville_settings[api_rate_limit_window]"
								   value="<?php echo esc_attr($rate_limit_window); ?>"
								   min="10"
								   max="3600"
								   class="small-text" />
							<?php esc_html_e('seconds', 'baskerville-ai-security'); ?>
							<p class="description">
								<?php esc_html_e('Time window for the rate limit (60 seconds = 1 minute).', 'baskerville-ai-security'); ?>
							</p>
						</td>
					</tr>
				</table>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-lg">
					<strong><?php esc_html_e('Current Configuration:', 'baskerville-ai-security'); ?></strong>
					<?php if ($rate_limit_enabled): ?>
						<p class="baskerville-mt-5 baskerville-mb-0">
							<?php
							echo sprintf(
								/* translators: %1$d is number of requests, %2$d is time in seconds */
								esc_html__('Rate limiting is ENABLED: %1$d requests per %2$d seconds per IP address', 'baskerville-ai-security'),
								esc_attr($rate_limit_requests),
								esc_attr($rate_limit_window)
							);
							?>
						</p>
					<?php else: ?>
						<p class="baskerville-mt-5 baskerville-mb-0 baskerville-text-danger">
							<?php esc_html_e('Rate limiting is DISABLED: API endpoints have no rate limits', 'baskerville-ai-security'); ?>
						</p>
					<?php endif; ?>
				</div>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg">
					<strong>💡 <?php esc_html_e('Recommended Settings:', 'baskerville-ai-security'); ?></strong>
					<ul class="baskerville-my-10">
						<li><strong><?php esc_html_e('Low Traffic:', 'baskerville-ai-security'); ?></strong> 100 requests/60s</li>
						<li><strong><?php esc_html_e('Medium Traffic:', 'baskerville-ai-security'); ?></strong> 500 requests/60s</li>
						<li><strong><?php esc_html_e('High Traffic:', 'baskerville-ai-security'); ?></strong> 1000 requests/60s</li>
					</ul>
					<p class="baskerville-mt-5 baskerville-mb-0">
						<?php esc_html_e('IPs in the Allow List bypass rate limiting completely.', 'baskerville-ai-security'); ?>
					</p>
				</div>

				<p class="submit">
					<input type="submit" name="submit" id="submit" class="button button-primary" value="<?php esc_attr_e('Save API Settings', 'baskerville-ai-security'); ?>">
				</p>
			</div>
		</div>
		<?php
	}

	public function ajax_run_benchmark() {
		try {
			check_ajax_referer('baskerville_benchmark', 'nonce');

			if (!current_user_can('manage_options')) {
				wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville-ai-security')));
				return;
			}

			$test = isset($_POST['test']) ? sanitize_text_field(wp_unslash($_POST['test'])) : '';

			if (empty($test)) {
				wp_send_json_error(array('message' => esc_html__('No test specified.', 'baskerville-ai-security')));
				return;
			}

			// Ensure classes are loaded
			if (!class_exists('Baskerville_Core')) {
				wp_send_json_error(array('message' => esc_html__('Baskerville_Core class not found.', 'baskerville-ai-security')));
				return;
			}

			$core = new Baskerville_Core();
			$aiua = null;

			// Only load AI_UA if needed
			if (in_array($test, array('ai-ua', 'firewall', 'all'), true)) {
				if (!class_exists('Baskerville_AI_UA')) {
					wp_send_json_error(array('message' => esc_html__('Baskerville_AI_UA class not found.', 'baskerville-ai-security')));
					return;
				}
				$aiua = new Baskerville_AI_UA($core);
			}

			$results = array();

			switch ($test) {
				case 'geoip':
					$results = $this->benchmark_geoip($core);
					break;

				case 'ai-ua':
					$results = $this->benchmark_ai_ua($aiua);
					break;

				case 'cache':
					$results = $this->benchmark_cache($core);
					break;

				case 'firewall':
					$results = $this->benchmark_firewall($core, $aiua);
					break;

				case 'all':
					$results = array(
						'geoip' => $this->benchmark_geoip($core),
						'ai-ua' => $this->benchmark_ai_ua($aiua),
						'cache' => $this->benchmark_cache($core),
						'firewall' => $this->benchmark_firewall($core, $aiua),
					);

					$message = '<div class="baskerville-text-left">';
					$message .= '<strong>' . esc_html__( 'GeoIP:', 'baskerville-ai-security' ) . '</strong> ' . esc_html($results['geoip']['message']) . '<br>';
					$message .= '<strong>' . esc_html__( 'AI/UA:', 'baskerville-ai-security' ) . '</strong> ' . esc_html($results['ai-ua']['message']) . '<br>';
					$message .= '<strong>' . esc_html__( 'Cache:', 'baskerville-ai-security' ) . '</strong> ' . esc_html($results['cache']['message']) . '<br>';
					$message .= '<strong>' . esc_html__( 'Firewall:', 'baskerville-ai-security' ) . '</strong> ' . esc_html($results['firewall']['message']);
					$message .= '</div>';

					wp_send_json_success(array(
						'message' => $message,
						'results' => $results
					));
					return;

				default:
					/* translators: %s is the invalid test type name */
				wp_send_json_error(array('message' => sprintf(esc_html__('Invalid test type: %s', 'baskerville-ai-security'), esc_html($test))));
					return;
			}

			// Check if benchmark returned error
			if (isset($results['error']) && $results['error']) {
				wp_send_json_error($results);
				return;
			}

			wp_send_json_success($results);

		} catch (Exception $e) {
			// error_log('Baskerville benchmark error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
			wp_send_json_error(array(
				/* translators: %s is the error message */
			'message' => sprintf(esc_html__('Benchmark failed: %s', 'baskerville-ai-security'), $e->getMessage()),
				'file' => basename($e->getFile()),
				'line' => $e->getLine()
			));
		} catch (Error $e) {
			// error_log('Baskerville benchmark fatal error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
			wp_send_json_error(array(
				/* translators: %s is the error message */
			'message' => sprintf(esc_html__('Fatal error: %s', 'baskerville-ai-security'), $e->getMessage()),
				'file' => basename($e->getFile()),
				'line' => $e->getLine()
			));
		}
	}

	private function benchmark_geoip($core) {
		$iterations = 100;
		$test_ips = array(
			'8.8.8.8',      // US
			'1.1.1.1',      // AU
			'185.60.216.35',// IT
			'45.33.32.156', // US
			'104.28.0.1',   // US
		);

		try {
			$start = microtime(true);
			for ($i = 0; $i < $iterations; $i++) {
				$ip = $test_ips[$i % count($test_ips)];
				$core->get_country_by_ip($ip);
			}
			$duration = microtime(true) - $start;

			$avg_ms = ($duration / $iterations) * 1000;
			$message = sprintf('%.2f ms avg (%.3f sec total)', $avg_ms, $duration);

			return array('message' => $message, 'avg_ms' => $avg_ms, 'total_sec' => $duration);
		} catch (Exception $e) {
			return array('message' => 'GeoIP test failed: ' . $e->getMessage(), 'error' => true);
		}
	}

	private function benchmark_ai_ua($aiua) {
		$iterations = 100;
		$test_uas = array(
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
			'curl/7.68.0',
			'python-requests/2.28.0',
			'Googlebot/2.1',
			'facebookexternalhit/1.1',
		);

		try {
			$start = microtime(true);
			for ($i = 0; $i < $iterations; $i++) {
				$ua = $test_uas[$i % count($test_uas)];
				$headers = array('user_agent' => $ua, 'accept' => 'text/html', 'accept_language' => 'en-US');
				$aiua->classify_client(array('fingerprint' => array()), array('headers' => $headers));
			}
			$duration = microtime(true) - $start;

			$avg_ms = ($duration / $iterations) * 1000;
			$message = sprintf('%.2f ms avg (%.3f sec total)', $avg_ms, $duration);

			return array('message' => $message, 'avg_ms' => $avg_ms, 'total_sec' => $duration);
		} catch (Exception $e) {
			return array('message' => 'AI/UA test failed: ' . $e->getMessage(), 'error' => true);
		}
	}

	private function benchmark_cache($core) {
		// Use fewer iterations for file cache (slower), more for APCu
		$cache_type = $core->fc_has_apcu() ? 'APCu' : 'File';
		$iterations = $cache_type === 'APCu' ? 1000 : 100;

		try {
			// Test SET operations
			$start = microtime(true);
			for ($i = 0; $i < $iterations; $i++) {
				$core->fc_set("benchmark_test_{$i}", array('data' => 'test'), 60);
			}
			$set_duration = microtime(true) - $start;

			// Test GET operations
			$start = microtime(true);
			for ($i = 0; $i < $iterations; $i++) {
				$core->fc_get("benchmark_test_{$i}");
			}
			$get_duration = microtime(true) - $start;

			// Cleanup
			for ($i = 0; $i < $iterations; $i++) {
				$core->fc_delete("benchmark_test_{$i}");
			}

			$set_avg_ms = ($set_duration / $iterations) * 1000;
			$get_avg_ms = ($get_duration / $iterations) * 1000;

			$message = sprintf('%s: SET %.3f ms, GET %.3f ms avg (%d ops)',
				$cache_type, $set_avg_ms, $get_avg_ms, $iterations);

			return array(
				'message' => $message,
				'cache_type' => $cache_type,
				'set_avg_ms' => $set_avg_ms,
				'get_avg_ms' => $get_avg_ms,
				'iterations' => $iterations
			);
		} catch (Exception $e) {
			return array(
				'message' => 'Cache test failed: ' . $e->getMessage(),
				'cache_type' => $cache_type,
				'error' => true
			);
		}
	}

	private function benchmark_firewall($core, $aiua) {
		$iterations = 100;

		try {
			$start = microtime(true);
			for ($i = 0; $i < $iterations; $i++) {
				// Simulate typical firewall operations
				$ip = '8.8.8.' . ($i % 255);

				// GeoIP lookup
				$country = $core->get_country_by_ip($ip);

				// UA classification
				$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
				$headers = array(
					'user_agent' => $ua,
					'accept' => 'text/html',
					'accept_language' => 'en-US'
				);
				$classification = $aiua->classify_client(array('fingerprint' => array()), array('headers' => $headers));

				// Cache check
				$ban = $core->fc_get("ban:{$ip}");

				// FP cookie check
				$fp_seen = $core->fc_get("fp_seen_ip:{$ip}");
			}
			$duration = microtime(true) - $start;

			$avg_ms = ($duration / $iterations) * 1000;
			$message = sprintf('%.2f ms avg (%.3f sec total)', $avg_ms, $duration);

			return array('message' => $message, 'avg_ms' => $avg_ms, 'total_sec' => $duration);
		} catch (Exception $e) {
			return array('message' => 'Firewall test failed: ' . $e->getMessage(), 'error' => true);
		}
	}

	public function render_honeypot_enabled_field() {
		$options = get_option('baskerville_settings', array());
		// Default to true if not set
		$enabled = !isset($options['honeypot_enabled']) || $options['honeypot_enabled'];
		?>
		<hr class="baskerville-hr">
		<h3 class="baskerville-subsection-title">🍯 <?php esc_html_e('Honeypot Trap', 'baskerville-ai-security'); ?></h3>
		<p class="description">
			<?php esc_html_e('Catch AI bots accessing hidden links', 'baskerville-ai-security'); ?>
		</p>
		<label>
			<input type="checkbox"
				   name="baskerville_settings[honeypot_enabled]"
				   value="1"
				   <?php checked($enabled, true); ?> />
			<?php esc_html_e('Enable honeypot trap', 'baskerville-ai-security'); ?>
		</label>
		<p class="description">
			<?php esc_html_e('Adds a hidden link to your site footer that is invisible to humans but visible to AI crawlers in HTML.', 'baskerville-ai-security'); ?><br>
			<?php esc_html_e('When an IP accesses this link, it is immediately marked as an AI bot.', 'baskerville-ai-security'); ?><br>
			<strong><?php esc_html_e('Honeypot URL:', 'baskerville-ai-security'); ?></strong> <code><?php echo esc_html(home_url('/ai-training-data/')); ?></code><br>
			<em class="baskerville-desc-danger"><?php esc_html_e('⚠️ The URL name "ai-training-data" is designed to attract AI bots looking for training content!', 'baskerville-ai-security'); ?></em><br>
			<strong class="baskerville-desc-danger">⚠️ <?php esc_html_e( 'IMPORTANT:', 'baskerville-ai-security' ); ?></strong> <?php esc_html_e( 'After enabling, go to', 'baskerville-ai-security' ); ?>
			<a href="<?php echo esc_url(admin_url('options-permalink.php')); ?>" target="_blank"><?php esc_html_e( 'Settings → Permalinks', 'baskerville-ai-security' ); ?></a>
			<?php esc_html_e( 'and click "Save Changes" to activate the honeypot URL!', 'baskerville-ai-security' ); ?>
		</p>
		<?php
	}

	public function render_honeypot_ban_field() {
		$options = get_option('baskerville_settings', array());
		// Default to true if not set
		$ban_enabled = !isset($options['honeypot_ban']) || $options['honeypot_ban'];
		?>
		<label>
			<input type="checkbox"
				   name="baskerville_settings[honeypot_ban]"
				   value="1"
				   <?php checked($ban_enabled, true); ?> />
			<?php esc_html_e('Ban IPs that trigger honeypot', 'baskerville-ai-security'); ?>
		</label>
		<p class="description">
			<?php esc_html_e('When enabled, IPs accessing the honeypot will be banned for 24 hours.', 'baskerville-ai-security'); ?><br>
			<?php esc_html_e('When disabled, the visit is still logged as AI bot.', 'baskerville-ai-security'); ?>
		</p>
		<?php
	}

	public function render_burst_protection_content() {
		// Get current thresholds
		$nocookie_threshold = (int) get_option('baskerville_nocookie_threshold', 10);
		$nocookie_window = (int) get_option('baskerville_nocookie_window_sec', 60);
		$nojs_threshold = (int) get_option('baskerville_nojs_threshold', 20);
		$nojs_window = (int) get_option('baskerville_nojs_window_sec', 60);
		$ban_ttl = (int) get_option('baskerville_ban_ttl_sec', 600);
		?>

		<div class="baskerville-alert baskerville-alert-info baskerville-alert-lg">
			<h4 class="baskerville-mt-0"><?php esc_html_e('What is Burst Protection?', 'baskerville-ai-security'); ?></h4>
			<p><?php esc_html_e('Burst protection prevents abuse by blocking IPs that make too many requests too quickly. When the Master Switch is ON, burst protection will automatically block suspicious traffic patterns.', 'baskerville-ai-security'); ?></p>

			<p><?php esc_html_e('When an IP exceeds the threshold, it receives a 403 Forbidden response and is temporarily banned. All burst types are counted separately per IP address using sliding time windows.', 'baskerville-ai-security'); ?></p>

			<strong><?php esc_html_e('4 Types of Burst Protection:', 'baskerville-ai-security'); ?></strong>
			<table class="baskerville-burst-table">
				<thead>
					<tr>
						<th><?php esc_html_e('Type', 'baskerville-ai-security'); ?></th>
						<th><?php esc_html_e('Trigger Condition', 'baskerville-ai-security'); ?></th>
						<th><?php esc_html_e('Purpose', 'baskerville-ai-security'); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><strong><?php esc_html_e('No-Cookie Burst', 'baskerville-ai-security'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville-ai-security'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s without valid cookie', 'baskerville-ai-security'); ?>
						</td>
						<td><?php esc_html_e('Blocks bots that don\'t accept cookies', 'baskerville-ai-security'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('No-JS Burst', 'baskerville-ai-security'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nojs_threshold); ?> <?php esc_html_e('requests', 'baskerville-ai-security'); ?>/<?php echo esc_html($nojs_window); ?><?php esc_html_e('s without JavaScript', 'baskerville-ai-security'); ?>
						</td>
						<td><?php esc_html_e('Blocks bots that don\'t execute JavaScript', 'baskerville-ai-security'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Non-Browser UA Burst', 'baskerville-ai-security'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville-ai-security'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s with non-browser User-Agent', 'baskerville-ai-security'); ?>
						</td>
						<td><?php esc_html_e('Blocks scripts (curl, wget, python-requests, etc.)', 'baskerville-ai-security'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Bad Bot Burst', 'baskerville-ai-security'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville-ai-security'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s for classified bad bots', 'baskerville-ai-security'); ?>
						</td>
						<td><?php esc_html_e('Aggressive blocking for known malicious bots', 'baskerville-ai-security'); ?></td>
					</tr>
				</tbody>
			</table>

			<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
				<strong>💡 <?php esc_html_e('How it works:', 'baskerville-ai-security'); ?></strong>
				<ul class="baskerville-list-spaced">
					<li><?php esc_html_e('Each burst type is counted separately per IP address', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Uses sliding time windows (not fixed intervals)', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('Verified crawlers (Google, Bing, etc.) bypass all burst protection', 'baskerville-ai-security'); ?></li>
					<li><?php esc_html_e('IPs in Allow List bypass all burst protection', 'baskerville-ai-security'); ?></li>
				</ul>
			</div>

			<div class="baskerville-danger-box">
				<strong>⚠️ <?php esc_html_e('For Testing:', 'baskerville-ai-security'); ?></strong>
				<?php esc_html_e('If you\'re testing with scripts or non-browser tools, add your IP to the', 'baskerville-ai-security'); ?>
				<strong><?php esc_html_e('IP Allow List', 'baskerville-ai-security'); ?></strong>
				<?php esc_html_e('tab to bypass all protection.', 'baskerville-ai-security'); ?>
			</div>
		</div>

		<!-- Burst Protection Thresholds Configuration -->
		<div class="baskerville-form-container">
			<h4 class="baskerville-mt-0"><?php esc_html_e('Burst Protection Thresholds', 'baskerville-ai-security'); ?></h4>
			<p class="description"><?php esc_html_e('Configure the thresholds for each burst protection type. Lower values = more aggressive protection.', 'baskerville-ai-security'); ?></p>

			<table class="form-table baskerville-mt-20">
				<tr>
					<th scope="row" colspan="2">
						<strong><?php esc_html_e('No-Cookie & Non-Browser UA Burst', 'baskerville-ai-security'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="nocookie_threshold">
							<?php esc_html_e('Request Limit', 'baskerville-ai-security'); ?>
						</label>
					</td>
					<td>
						<input type="number"
							   id="nocookie_threshold"
							   name="baskerville_nocookie_threshold"
							   value="<?php echo esc_attr($nocookie_threshold); ?>"
							   min="1"
							   max="1000"
							   class="small-text" />
						<?php esc_html_e('requests per', 'baskerville-ai-security'); ?>
						<input type="number"
							   id="nocookie_window"
							   name="baskerville_nocookie_window_sec"
							   value="<?php echo esc_attr($nocookie_window); ?>"
							   min="10"
							   max="3600"
							   class="small-text" />
						<?php esc_html_e('seconds', 'baskerville-ai-security'); ?>
						<p class="description">
							<?php esc_html_e('Default: 10 requests / 60 seconds. Applies to no-cookie, non-browser UA, and bad bot burst types.', 'baskerville-ai-security'); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row" colspan="2" class="baskerville-form-section-header">
						<strong><?php esc_html_e('No-JavaScript Burst', 'baskerville-ai-security'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="nojs_threshold">
							<?php esc_html_e('Request Limit', 'baskerville-ai-security'); ?>
						</label>
					</td>
					<td>
						<input type="number"
							   id="nojs_threshold"
							   name="baskerville_nojs_threshold"
							   value="<?php echo esc_attr($nojs_threshold); ?>"
							   min="1"
							   max="1000"
							   class="small-text" />
						<?php esc_html_e('requests per', 'baskerville-ai-security'); ?>
						<input type="number"
							   id="nojs_window"
							   name="baskerville_nojs_window_sec"
							   value="<?php echo esc_attr($nojs_window); ?>"
							   min="10"
							   max="3600"
							   class="small-text" />
						<?php esc_html_e('seconds', 'baskerville-ai-security'); ?>
						<p class="description">
							<?php esc_html_e('Default: 20 requests / 60 seconds. Applies when JavaScript fingerprint is not received.', 'baskerville-ai-security'); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row" colspan="2" class="baskerville-form-section-header">
						<strong><?php esc_html_e('Ban Duration', 'baskerville-ai-security'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="ban_ttl">
							<?php esc_html_e('Ban TTL', 'baskerville-ai-security'); ?>
						</label>
					</td>
					<td>
						<input type="number"
							   id="ban_ttl"
							   name="baskerville_ban_ttl_sec"
							   value="<?php echo esc_attr($ban_ttl); ?>"
							   min="60"
							   max="86400"
							   class="small-text" />
						<?php esc_html_e('seconds', 'baskerville-ai-security'); ?>
						<p class="description">
							<?php esc_html_e('Default: 600 seconds (10 minutes). How long to ban IPs that trigger burst protection.', 'baskerville-ai-security'); ?>
						</p>
					</td>
				</tr>
			</table>
		</div>
		<?php
	}

	/**
	 * AJAX: Get live feed of recent bot blocks.
	 *
	 * Direct database queries are required for real-time AJAX feed.
	 * Caching is not applicable for live data updates.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function ajax_get_live_feed() {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';

		// Get last 30 unique IPs (blocked/suspicious) - one event per IP
		// Note: using classification_reason (actual column name), aliasing as 'reason' for frontend
		// Use subquery to get the latest record for each IP

		$events = $wpdb->get_results($wpdb->prepare(
			"SELECT t1.ip, t1.country_code, t1.classification, t1.classification_reason as reason,
					t1.score, t1.user_agent as ua, UNIX_TIMESTAMP(t1.created_at) as timestamp,
					t1.event_type, t1.block_reason
			 FROM " . esc_sql($table) . " t1
			 INNER JOIN (
				 SELECT ip, MAX(created_at) as max_created
				 FROM " . esc_sql($table) . "
				 WHERE classification IN ('bad_bot', 'ai_bot', 'bot') OR score >= 50 OR (block_reason IS NOT NULL AND block_reason != '') OR event_type = 'ts_fail'
				 GROUP BY ip
			 ) t2 ON t1.ip = t2.ip AND t1.created_at = t2.max_created
			 WHERE (t1.classification IN ('bad_bot', 'ai_bot', 'bot') OR t1.score >= 50 OR (t1.block_reason IS NOT NULL AND t1.block_reason != '') OR t1.event_type = 'ts_fail')
			 ORDER BY t1.created_at DESC
			 LIMIT %d",
			30
		), ARRAY_A);

		// Convert timestamps to ISO 8601 format for JavaScript
		foreach ($events as &$event) {
			if (!empty($event['timestamp'])) {
				// Convert UNIX timestamp to ISO 8601 UTC format
				$event['created_at'] = gmdate('Y-m-d\TH:i:s\Z', $event['timestamp']);
				unset($event['timestamp']);
			}
			// Add banned flag
			$event['is_banned'] = !empty($event['block_reason']);
		}

		wp_send_json_success($events);
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery

	/**
	 * AJAX: Get live statistics.
	 *
	 * Direct database queries are required for real-time AJAX statistics.
	 * Caching is not applicable for live data updates.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function ajax_get_live_stats() {
		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';

		// Blocks today

		$blocks_today = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM " . esc_sql($table) . "
			 WHERE classification IN ('bad_bot', 'ai_bot')
			   AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)"
		);

		// Blocks last hour

		$blocks_hour = (int) $wpdb->get_var(
			"SELECT COUNT(*) FROM " . esc_sql($table) . "
			 WHERE classification IN ('bad_bot', 'ai_bot')
			   AND created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)"
		);

		// Top attacking IPs today

		$top_ips = $wpdb->get_results(
			"SELECT ip, country_code, COUNT(*) as count
			 FROM " . esc_sql($table) . "
			 WHERE classification IN ('bad_bot', 'ai_bot')
			   AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
			 GROUP BY ip
			 ORDER BY count DESC
			 LIMIT 5",
			ARRAY_A
		);

		// Top attacking countries today

		$top_countries = $wpdb->get_results(
			"SELECT country_code, COUNT(*) as count
			 FROM " . esc_sql($table) . "
			 WHERE classification IN ('bad_bot', 'ai_bot')
			   AND created_at >= DATE_SUB(NOW(), INTERVAL 24 HOUR)
			 GROUP BY country_code
			 ORDER BY count DESC
			 LIMIT 5",
			ARRAY_A
		);

		// Add country names
		$all_countries = $this->get_countries_list();
		foreach ($top_countries as &$country) {
			$code = $country['country_code'] ?? '';
			$country['country_name'] = isset($all_countries[$code]) ? $all_countries[$code] : $code;
		}

		wp_send_json_success([
			'blocks_today'  => $blocks_today,
			'blocks_hour'   => $blocks_hour,
			'top_ips'       => $top_ips,
			'top_countries' => $top_countries
		]);
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery

	public function ajax_import_logs() {
		check_ajax_referer('baskerville_import_logs', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__( 'Insufficient permissions.', 'baskerville-ai-security' )));
		}

		$core = new Baskerville_Core();
		$aiua = new Baskerville_AI_UA($core);
		$stats = new Baskerville_Stats($core, $aiua);

		$imported = $stats->process_log_files_to_db();

		// Store last import time
		if ($imported > 0) {
			update_option('baskerville_last_log_import', time());
		}

		wp_send_json_success(array(
			'message' => sprintf(
				/* translators: %d is the number of records imported */
				__('Successfully imported %d records from log files', 'baskerville-ai-security'),
				$imported
			),
			'imported' => $imported
		));
	}

	/**
	 * AJAX: IP Lookup for troubleshooting.
	 *
	 * Direct database queries are required for IP lookup functionality.
	 *
	 * @phpcs:disable WordPress.DB.DirectDatabaseQuery
	 */
	public function ajax_ip_lookup() {
		// Verify nonce
		if (!wp_verify_nonce(sanitize_text_field(wp_unslash($_POST['_wpnonce'] ?? '')), 'baskerville_ip_lookup')) {
			wp_send_json_error(esc_html__('Security check failed.', 'baskerville-ai-security'));
		}

		// Check permissions
		if (!current_user_can('manage_options')) {
			wp_send_json_error(esc_html__('Insufficient permissions.', 'baskerville-ai-security'));
		}

		// Get and validate IP
		$ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
		if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
			wp_send_json_error(esc_html__('Invalid IP address.', 'baskerville-ai-security'));
		}

		global $wpdb;
		$table = $wpdb->prefix . 'baskerville_stats';

		// Check if IP is currently banned (in cache)
		$core = new Baskerville_Core();
		$ban_data = $core->fc_get("ban:{$ip}");
		$is_banned = !empty($ban_data);

		// Get country from most recent record
		$country = $wpdb->get_var($wpdb->prepare(
			"SELECT country_code FROM " . esc_sql($table) . " WHERE ip = %s ORDER BY created_at DESC LIMIT 1",
			$ip
		));

		// Get total events count
		$total_events = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(*) FROM " . esc_sql($table) . " WHERE ip = %s",
			$ip
		));

		// Get block events count
		$block_events = (int) $wpdb->get_var($wpdb->prepare(
			"SELECT COUNT(*) FROM " . esc_sql($table) . " WHERE ip = %s AND block_reason IS NOT NULL AND block_reason != ''",
			$ip
		));

		// Get recent events (last 100)
		$events = $wpdb->get_results($wpdb->prepare(
			"SELECT created_at, classification, score, block_reason, user_agent
			 FROM " . esc_sql($table) . "
			 WHERE ip = %s
			 ORDER BY created_at DESC
			 LIMIT 100",
			$ip
		), ARRAY_A);

		// Format events for frontend
		$formatted_events = array();
		foreach ($events as $event) {
			$formatted_events[] = array(
				'timestamp'      => $event['created_at'],
				'classification' => $event['classification'] ?? 'unknown',
				'score'          => (int) ($event['score'] ?? 0),
				'block_reason'   => $event['block_reason'] ?? '',
				'user_agent'     => $event['user_agent'] ?? '',
			);
		}

		wp_send_json_success(array(
			'is_banned'    => $is_banned,
			'country'      => $country ?: '',
			'total_events' => $total_events,
			'block_events' => $block_events,
			'events'       => $formatted_events,
		));
	}
	// @phpcs:enable WordPress.DB.DirectDatabaseQuery
}