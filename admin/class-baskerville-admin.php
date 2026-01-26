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
		add_action('admin_init', array($this, 'register_settings'));
		add_action('wp_ajax_baskerville_install_maxmind', array($this, 'ajax_install_maxmind'));
		add_action('wp_ajax_baskerville_clear_geoip_cache', array($this, 'ajax_clear_geoip_cache'));
		add_action('wp_ajax_baskerville_run_benchmark', array($this, 'ajax_run_benchmark'));
		add_action('wp_ajax_baskerville_get_live_feed', array($this, 'ajax_get_live_feed'));
		add_action('wp_ajax_baskerville_get_live_stats', array($this, 'ajax_get_live_stats'));
		add_action('wp_ajax_baskerville_import_logs', array($this, 'ajax_import_logs'));
		add_action('wp_ajax_baskerville_ip_lookup', array($this, 'ajax_ip_lookup'));
		add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
	}

	public function enqueue_admin_scripts($hook) {
		// Only load on our settings page
		if ($hook !== 'settings_page_baskerville-settings') {
			return;
		}

		// Enqueue Select2 (local files)
		wp_enqueue_style('select2', BASKERVILLE_PLUGIN_URL . 'assets/css/select2.min.css', array(), '4.1.0');
		wp_enqueue_script('select2', BASKERVILLE_PLUGIN_URL . 'assets/js/select2.min.js', array('jquery'), '4.1.0', false );

		// Enqueue Chart.js (local file)
		wp_enqueue_script('chartjs', BASKERVILLE_PLUGIN_URL . 'assets/js/chart.min.js', array(), '4.4.0', true);

		// Pass nonce and i18n strings to admin.js
		wp_localize_script('select2', 'baskervilleAdmin', array(
			'importLogsNonce' => wp_create_nonce('baskerville_import_logs'),
			'i18n' => array(
				'importing'     => esc_html__( 'Importing...', 'baskerville' ),
				'importFailed'  => esc_html__( 'Import failed', 'baskerville' ),
				'importLogsNow' => esc_html__( 'Import Logs Now', 'baskerville' ),
				'ajaxError'     => esc_html__( 'AJAX error occurred', 'baskerville' ),
			),
		));
	}

	public function add_admin_menu() {
		add_options_page(
			esc_html__('Baskerville Settings', 'baskerville'),
			esc_html__('Baskerville', 'baskerville'),
			'manage_options',
			'baskerville-settings',
			array($this, 'admin_page')
		);
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
		// 	esc_html__('Enable API Rate Limiting', 'baskerville'),
		// 	array($this, 'render_api_rate_limit_enabled_field'),
		// 	'baskerville-rate-limits',
		// 	'baskerville_rate_limits_section'
		// );

		// ===== Settings Tab =====
		add_settings_section(
			'baskerville_settings_section',
			esc_html__('General Settings', 'baskerville'),
			null,
			'baskerville-settings'
		);

		// Ban duration field
		add_settings_field(
			'ban_ttl_sec',
			esc_html__('Ban Duration', 'baskerville'),
			array($this, 'render_ban_duration_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// Log page visits field
		add_settings_field(
			'log_page_visits',
			esc_html__('Logging Mode', 'baskerville'),
			array($this, 'render_log_page_visits_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// Data retention field
		add_settings_field(
			'retention_days',
			esc_html__('Data Retention', 'baskerville'),
			array($this, 'render_retention_days_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// IP Whitelist field
		add_settings_field(
			'ip_whitelist',
			esc_html__('Allowed IPs', 'baskerville'),
			array($this, 'render_ip_whitelist_field'),
			'baskerville-settings',
			'baskerville_settings_section'
		);

		// ===== Country Control Tab =====
		add_settings_section(
			'baskerville_country_control_section',
			esc_html__('Country Control Settings', 'baskerville'),
			null,
			'baskerville-country-control'
		);

		// Note: geoip_enabled is now rendered manually at the top of the Country Control tab
		// add_settings_field(
		// 	'geoip_enabled',
		// 	esc_html__('Enable Country Control', 'baskerville'),
		// 	array($this, 'render_geoip_enabled_field'),
		// 	'baskerville-country-control',
		// 	'baskerville_country_control_section'
		// );

		add_settings_field(
			'geoip_mode',
			esc_html__('GeoIP Access Mode', 'baskerville'),
			array($this, 'render_geoip_mode_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		add_settings_field(
			'blacklist_countries',
			esc_html__('Block List Countries', 'baskerville'),
			array($this, 'render_blacklist_countries_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		add_settings_field(
			'whitelist_countries',
			esc_html__('Allow List Countries', 'baskerville'),
			array($this, 'render_whitelist_countries_field'),
			'baskerville-country-control',
			'baskerville_country_control_section'
		);

		// ===== AI Bot Control Tab =====
		add_settings_section(
			'baskerville_ai_bot_control_section',
			esc_html__('AI Bot Access Control', 'baskerville'),
			array($this, 'render_ai_bot_control_section'),
			'baskerville-ai-bot-control'
		);

		// ai_bot_control_enabled - now rendered manually at top of form

		add_settings_field(
			'ai_bot_blocking_mode',
			esc_html__('AI Bot Access Mode', 'baskerville'),
			array($this, 'render_ai_bot_mode_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'blacklist_ai_companies',
			esc_html__('Block List Companies', 'baskerville'),
			array($this, 'render_blacklist_ai_companies_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'whitelist_ai_companies',
			esc_html__('Allow List Companies', 'baskerville'),
			array($this, 'render_whitelist_ai_companies_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		// Honeypot fields (moved from general settings)
		add_settings_field(
			'honeypot_enabled',
			esc_html__('Honeypot Trap', 'baskerville'),
			array($this, 'render_honeypot_enabled_field'),
			'baskerville-ai-bot-control',
			'baskerville_ai_bot_control_section'
		);

		add_settings_field(
			'honeypot_ban',
			esc_html__('Ban on Honeypot Trigger', 'baskerville'),
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

		// Honeypot settings - preserve existing if not in input
		$sanitized['honeypot_enabled'] = isset($input['honeypot_enabled'])
			? (bool) $input['honeypot_enabled']
			: (isset($existing['honeypot_enabled']) ? $existing['honeypot_enabled'] : false);
		$sanitized['honeypot_ban'] = isset($input['honeypot_ban'])
			? (bool) $input['honeypot_ban']
			: (isset($existing['honeypot_ban']) ? $existing['honeypot_ban'] : false);

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
			<?php esc_html_e('Enable 403 ban for detected bots', 'baskerville'); ?>
		</label>
		<?php
	}

	public function render_log_page_visits_field() {
		$options = get_option('baskerville_settings', array());
		// Default to 'database' for immediate blocking and analytics
		$mode = isset($options['log_mode']) ? $options['log_mode'] : 'database';
		?>
		<fieldset>
			<legend class="screen-reader-text"><span><?php esc_html_e('Page Visit Logging Mode', 'baskerville'); ?></span></legend>

			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[log_mode]"
					   value="disabled"
					   <?php checked($mode, 'disabled'); ?> />
				<strong><?php esc_html_e('Disabled', 'baskerville'); ?></strong> -
				<?php esc_html_e('No page visit logging (blocks & fingerprints still logged)', 'baskerville'); ?>
				<span class="baskerville-text-success"><?php esc_html_e( '⚡ ~0ms overhead', 'baskerville' ); ?></span>
			</label>

			<label class="baskerville-label-block">
				<input type="radio" name="baskerville_settings[log_mode]" value="file" <?php checked($mode, 'file'); ?> />
				<strong><?php esc_html_e('File Logging', 'baskerville'); ?></strong> -
				<?php esc_html_e('Write to log file, batch import to DB every minute', 'baskerville'); ?>
				<span class="baskerville-text-success"><?php esc_html_e('⚡ ~1-2ms overhead', 'baskerville'); ?></span>
				<strong class="baskerville-text-info"><?php esc_html_e('✓ Recommended', 'baskerville'); ?></strong>
			</label>

			<label class="baskerville-label-block">
				<input type="radio" name="baskerville_settings[log_mode]" value="database" <?php checked($mode, 'database'); ?> />
				<strong><?php esc_html_e('Direct Database', 'baskerville'); ?></strong> -
				<?php esc_html_e('Write to database immediately (high overhead)', 'baskerville'); ?>
				<span class="baskerville-text-warning"><?php esc_html_e('⚠️ ~500ms overhead on shared hosting', 'baskerville'); ?></span>
			</label>

			<p class="description baskerville-alert baskerville-alert-neutral baskerville-alert-xs baskerville-alert-mt">
				<strong><?php esc_html_e('💡 Recommendation:', 'baskerville'); ?></strong><br>
				<?php esc_html_e('Use <strong>File Logging</strong> for best performance on shared hosting (GoDaddy, Bluehost, etc.)', 'baskerville'); ?><br>
				<?php esc_html_e('Full analytics with minimal overhead. Logs are processed in background every minute.', 'baskerville'); ?>
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
				<strong><?php esc_html_e('Allow All Countries', 'baskerville'); ?></strong> -
				<?php esc_html_e('No GeoIP restrictions (allow all countries)', 'baskerville'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[geoip_mode]"
					   value="blacklist"
					   class="baskerville-geoip-mode-radio"
					   <?php checked($mode, 'blacklist'); ?> />
				<strong><?php esc_html_e('Block List', 'baskerville'); ?></strong> -
				<?php esc_html_e('Block access from specified countries', 'baskerville'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[geoip_mode]"
					   value="whitelist"
					   class="baskerville-geoip-mode-radio"
					   <?php checked($mode, 'whitelist'); ?> />
				<strong><?php esc_html_e('Allow List', 'baskerville'); ?></strong> -
				<?php esc_html_e('Allow access ONLY from specified countries', 'baskerville'); ?>
			</label>
		</fieldset>
		<p class="description">
			<?php esc_html_e('Choose whether to allow all countries, block specific countries, or allow only specific countries.', 'baskerville'); ?>
		</p>

		<script>
		jQuery(document).ready(function($) {
			// Initialize Select2 for country selects
			$('.baskerville-country-select').select2({
				placeholder: '<?php esc_html_e('Search and select countries...', 'baskerville'); ?>',
				allowClear: true,
				width: '100%'
			});

			function updateGeoIPFields() {
				var selectedMode = $('input[name="baskerville_settings[geoip_mode]"]:checked').val();

				var $blacklistField = $('#baskerville_blacklist_countries');
				var $whitelistField = $('#baskerville_whitelist_countries');
				var $blacklistContainer = $blacklistField.closest('div');
				var $whitelistContainer = $whitelistField.closest('div');

				// Reset all fields
				$blacklistField.prop('disabled', true);
				$whitelistField.prop('disabled', true);
				$blacklistContainer.css('opacity', '0.5');
				$whitelistContainer.css('opacity', '0.5');

				// Enable appropriate field based on mode
				if (selectedMode === 'blacklist') {
					$blacklistField.prop('disabled', false);
					$blacklistContainer.css('opacity', '1');
				} else if (selectedMode === 'whitelist') {
					$whitelistField.prop('disabled', false);
					$whitelistContainer.css('opacity', '1');
				}
			}

			// Update on radio button change
			$('.baskerville-geoip-mode-radio').on('change', updateGeoIPFields);

			// Update on page load
			updateGeoIPFields();
		});
		</script>
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
				<strong class="baskerville-text-danger"><?php esc_html_e('Block access from these countries', 'baskerville'); ?></strong><br>
				<?php esc_html_e('Search and select countries to block. You can select multiple countries.', 'baskerville'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Block List" mode is selected above.', 'baskerville'); ?></em><br>
				<strong><?php esc_html_e('Current GeoIP source:', 'baskerville'); ?></strong> <?php echo esc_html($geoip_source); ?>
				<?php if ($geoip_source === 'MaxMind (if configured)'): ?>
					<br><em><?php esc_html_e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville'); ?></em>
					<br><em><?php esc_html_e('Download from: ', 'baskerville'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank"><?php esc_html_e( 'MaxMind GeoLite2', 'baskerville'); ?></a></em>
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
				<strong class="baskerville-text-primary"><?php esc_html_e('Allow access ONLY from these countries', 'baskerville'); ?></strong><br>
				<?php esc_html_e('Search and select countries to allow. You can select multiple countries.', 'baskerville'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Allow List" mode is selected above.', 'baskerville'); ?></em><br>
				<strong><?php esc_html_e('Current GeoIP source:', 'baskerville'); ?></strong> <?php echo esc_html($geoip_source); ?>
				<?php if ($geoip_source === 'MaxMind (if configured)'): ?>
					<br><em><?php esc_html_e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville'); ?></em>
					<br><em><?php esc_html_e('Download from: ', 'baskerville'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank"><?php esc_html_e('MaxMind GeoLite2', 'baskerville'); ?></a></em>
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
				<?php esc_html_e('Bot Control', 'baskerville'); ?>
			</span>
			<input type="hidden" name="baskerville_settings[bot_protection_enabled]" value="0">
			<label class="baskerville-toggle-switch">
				<input type="checkbox" name="baskerville_settings[bot_protection_enabled]" value="1" <?php checked($enabled, true); ?> />
				<span class="baskerville-toggle-slider-regular"></span>
			</label>
			<span class="baskerville-toggle-text">
				<?php echo $enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
				<?php esc_html_e('Burst Protection', 'baskerville'); ?>
			</span>
			<input type="hidden" name="baskerville_settings[burst_protection_enabled]" value="0">
			<label class="baskerville-toggle-switch">
				<input type="checkbox" name="baskerville_settings[burst_protection_enabled]" value="1" <?php checked($enabled, true); ?> />
				<span class="baskerville-toggle-slider-regular"></span>
			</label>
			<span class="baskerville-toggle-text">
				<?php echo $enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
			<?php esc_html_e('Enable API rate limiting', 'baskerville'); ?>
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
			<?php esc_html_e('Enable country-based access control', 'baskerville'); ?>
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
			<?php esc_html_e('Enable AI bot crawler control', 'baskerville'); ?>
		</label>
		<?php
	}

	public function render_ban_duration_field() {
		$ban_ttl = (int) get_option('baskerville_ban_ttl_sec', 600);
		?>
		<input type="number" name="baskerville_ban_ttl_sec" value="<?php echo esc_attr($ban_ttl); ?>" min="1" max="86400" class="baskerville-input-md">
		<span><?php esc_html_e('seconds', 'baskerville'); ?></span>
		<p class="description">
			<?php esc_html_e('How long IP addresses are banned after triggering protection (1-86400 seconds)', 'baskerville'); ?>
		</p>
		<?php
	}

	public function render_retention_days_field() {
		$retention = $this->stats->get_retention_days();
		?>
		<input type="number" name="baskerville_retention_days" value="<?php echo esc_attr($retention); ?>" min="1" max="365" class="baskerville-input-md">
		<span><?php esc_html_e('days', 'baskerville'); ?></span>
		<p class="description">
			<?php esc_html_e('Statistics older than this will be automatically deleted (1-365 days)', 'baskerville'); ?>
		</p>
		<?php
	}

	public function render_ip_whitelist_field() {
		$whitelist = get_option('baskerville_ip_whitelist', '');
		?>
		<textarea name="baskerville_ip_whitelist" rows="5" cols="50" class="large-text code"><?php echo esc_textarea($whitelist); ?></textarea>
		<p class="description">
			<?php esc_html_e('IP addresses that bypass all checks (one per line or comma-separated)', 'baskerville'); ?>
		</p>
		<?php
	}

	public function render_ai_bot_control_section() {
		?>
		<p><?php esc_html_e('Control access from AI bot crawlers based on their company ownership.', 'baskerville'); ?></p>
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
				<strong><?php esc_html_e('Allow All AI Bots', 'baskerville'); ?></strong> -
				<?php esc_html_e('No AI bot restrictions (allow all companies)', 'baskerville'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="block_all"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'block_all'); ?> />
				<strong class="baskerville-text-danger"><?php esc_html_e('Block All AI Bots', 'baskerville'); ?></strong> -
				<?php esc_html_e('Block all AI bot crawlers (no exceptions)', 'baskerville'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="blacklist"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'blacklist'); ?> />
				<strong><?php esc_html_e('Block List', 'baskerville'); ?></strong> -
				<?php esc_html_e('Block access from specified companies', 'baskerville'); ?>
			</label>
			<label class="baskerville-label-block">
				<input type="radio"
					   name="baskerville_settings[ai_bot_blocking_mode]"
					   value="whitelist"
					   class="baskerville-aibot-mode-radio"
					   <?php checked($mode, 'whitelist'); ?> />
				<strong><?php esc_html_e('Allow List', 'baskerville'); ?></strong> -
				<?php esc_html_e('Allow access ONLY from specified companies', 'baskerville'); ?>
			</label>
		</fieldset>
		<p class="description">
			<?php esc_html_e('Choose whether to allow all AI bots, block all AI bots, block specific companies, or allow only specific companies.', 'baskerville'); ?>
		</p>

		<script>
		jQuery(document).ready(function($) {
			function updateAIBotFields() {
				var selectedMode = $('input[name="baskerville_settings[ai_bot_blocking_mode]"]:checked').val();

				var $blacklistField = $('#baskerville_blacklist_ai_companies');
				var $whitelistField = $('#baskerville_whitelist_ai_companies');
				var $blacklistContainer = $blacklistField.closest('div');
				var $whitelistContainer = $whitelistField.closest('div');

				// Reset all fields
				$blacklistField.prop('disabled', true);
				$whitelistField.prop('disabled', true);
				$blacklistContainer.css('opacity', '0.5');
				$whitelistContainer.css('opacity', '0.5');

				// Enable appropriate field based on mode
				// In 'block_all' mode, both fields remain disabled
				if (selectedMode === 'blacklist') {
					$blacklistField.prop('disabled', false);
					$blacklistContainer.css('opacity', '1');
				} else if (selectedMode === 'whitelist') {
					$whitelistField.prop('disabled', false);
					$whitelistContainer.css('opacity', '1');
				}
				// allow_all and block_all modes keep both fields disabled
			}

			$('.baskerville-aibot-mode-radio').on('change', updateAIBotFields);
			updateAIBotFields();
		});
		</script>
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
				<strong class="baskerville-text-danger"><?php esc_html_e('Block access from these AI bot companies', 'baskerville'); ?></strong><br>
				<?php esc_html_e('Search and select companies to block. You can select multiple companies.', 'baskerville'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Block List" mode is selected above.', 'baskerville'); ?></em>
			</p>
		</div>

		<script>
		jQuery(document).ready(function($) {
			$('.baskerville-aibot-select').select2({
				placeholder: '<?php esc_html_e('Search and select companies...', 'baskerville'); ?>',
				allowClear: true,
				width: '100%'
			});
		});
		</script>
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
				<strong class="baskerville-text-primary"><?php esc_html_e('Allow access ONLY from these AI bot companies', 'baskerville'); ?></strong><br>
				<?php esc_html_e('Search and select companies to allow. You can select multiple companies.', 'baskerville'); ?><br>
				<em class="baskerville-text-muted"><?php esc_html_e('This field is only active when "Allow List" mode is selected above.', 'baskerville'); ?></em>
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
		return 'MaxMind (if configured)';
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

		// Check MaxMind
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

		// Nothing available
		return array('source' => null, 'available' => false);
	}

	private function get_countries_list() {
		return array(
			'AF' => esc_html__('Afghanistan', 'baskerville'),
			'AL' => esc_html__('Albania', 'baskerville'),
			'DZ' => esc_html__('Algeria', 'baskerville'),
			'AS' => esc_html__('American Samoa', 'baskerville'),
			'AD' => esc_html__('Andorra', 'baskerville'),
			'AO' => esc_html__('Angola', 'baskerville'),
			'AI' => esc_html__('Anguilla', 'baskerville'),
			'AQ' => esc_html__('Antarctica', 'baskerville'),
			'AG' => esc_html__('Antigua and Barbuda', 'baskerville'),
			'AR' => esc_html__('Argentina', 'baskerville'),
			'AM' => esc_html__('Armenia', 'baskerville'),
			'AW' => esc_html__('Aruba', 'baskerville'),
			'AU' => esc_html__('Australia', 'baskerville'),
			'AT' => esc_html__('Austria', 'baskerville'),
			'AZ' => esc_html__('Azerbaijan', 'baskerville'),
			'BS' => esc_html__('Bahamas', 'baskerville'),
			'BH' => esc_html__('Bahrain', 'baskerville'),
			'BD' => esc_html__('Bangladesh', 'baskerville'),
			'BB' => esc_html__('Barbados', 'baskerville'),
			'BY' => esc_html__('Belarus', 'baskerville'),
			'BE' => esc_html__('Belgium', 'baskerville'),
			'BZ' => esc_html__('Belize', 'baskerville'),
			'BJ' => esc_html__('Benin', 'baskerville'),
			'BM' => esc_html__('Bermuda', 'baskerville'),
			'BT' => esc_html__('Bhutan', 'baskerville'),
			'BO' => esc_html__('Bolivia', 'baskerville'),
			'BA' => esc_html__('Bosnia and Herzegovina', 'baskerville'),
			'BW' => esc_html__('Botswana', 'baskerville'),
			'BR' => esc_html__('Brazil', 'baskerville'),
			'BN' => esc_html__('Brunei', 'baskerville'),
			'BG' => esc_html__('Bulgaria', 'baskerville'),
			'BF' => esc_html__('Burkina Faso', 'baskerville'),
			'BI' => esc_html__('Burundi', 'baskerville'),
			'KH' => esc_html__('Cambodia', 'baskerville'),
			'CM' => esc_html__('Cameroon', 'baskerville'),
			'CA' => esc_html__('Canada', 'baskerville'),
			'CV' => esc_html__('Cape Verde', 'baskerville'),
			'KY' => esc_html__('Cayman Islands', 'baskerville'),
			'CF' => esc_html__('Central African Republic', 'baskerville'),
			'TD' => esc_html__('Chad', 'baskerville'),
			'CL' => esc_html__('Chile', 'baskerville'),
			'CN' => esc_html__('China', 'baskerville'),
			'CO' => esc_html__('Colombia', 'baskerville'),
			'KM' => esc_html__('Comoros', 'baskerville'),
			'CG' => esc_html__('Congo', 'baskerville'),
			'CD' => esc_html__('Congo (DRC)', 'baskerville'),
			'CK' => esc_html__('Cook Islands', 'baskerville'),
			'CR' => esc_html__('Costa Rica', 'baskerville'),
			'CI' => esc_html__('Côte d\'Ivoire', 'baskerville'),
			'HR' => esc_html__('Croatia', 'baskerville'),
			'CU' => esc_html__('Cuba', 'baskerville'),
			'CY' => esc_html__('Cyprus', 'baskerville'),
			'CZ' => esc_html__('Czech Republic', 'baskerville'),
			'DK' => esc_html__('Denmark', 'baskerville'),
			'DJ' => esc_html__('Djibouti', 'baskerville'),
			'DM' => esc_html__('Dominica', 'baskerville'),
			'DO' => esc_html__('Dominican Republic', 'baskerville'),
			'EC' => esc_html__('Ecuador', 'baskerville'),
			'EG' => esc_html__('Egypt', 'baskerville'),
			'SV' => esc_html__('El Salvador', 'baskerville'),
			'GQ' => esc_html__('Equatorial Guinea', 'baskerville'),
			'ER' => esc_html__('Eritrea', 'baskerville'),
			'EE' => esc_html__('Estonia', 'baskerville'),
			'ET' => esc_html__('Ethiopia', 'baskerville'),
			'FK' => esc_html__('Falkland Islands', 'baskerville'),
			'FO' => esc_html__('Faroe Islands', 'baskerville'),
			'FJ' => esc_html__('Fiji', 'baskerville'),
			'FI' => esc_html__('Finland', 'baskerville'),
			'FR' => esc_html__('France', 'baskerville'),
			'GF' => esc_html__('French Guiana', 'baskerville'),
			'PF' => esc_html__('French Polynesia', 'baskerville'),
			'GA' => esc_html__('Gabon', 'baskerville'),
			'GM' => esc_html__('Gambia', 'baskerville'),
			'GE' => esc_html__('Georgia', 'baskerville'),
			'DE' => esc_html__('Germany', 'baskerville'),
			'GH' => esc_html__('Ghana', 'baskerville'),
			'GI' => esc_html__('Gibraltar', 'baskerville'),
			'GR' => esc_html__('Greece', 'baskerville'),
			'GL' => esc_html__('Greenland', 'baskerville'),
			'GD' => esc_html__('Grenada', 'baskerville'),
			'GP' => esc_html__('Guadeloupe', 'baskerville'),
			'GU' => esc_html__('Guam', 'baskerville'),
			'GT' => esc_html__('Guatemala', 'baskerville'),
			'GN' => esc_html__('Guinea', 'baskerville'),
			'GW' => esc_html__('Guinea-Bissau', 'baskerville'),
			'GY' => esc_html__('Guyana', 'baskerville'),
			'HT' => esc_html__('Haiti', 'baskerville'),
			'HN' => esc_html__('Honduras', 'baskerville'),
			'HK' => esc_html__('Hong Kong', 'baskerville'),
			'HU' => esc_html__('Hungary', 'baskerville'),
			'IS' => esc_html__('Iceland', 'baskerville'),
			'IN' => esc_html__('India', 'baskerville'),
			'ID' => esc_html__('Indonesia', 'baskerville'),
			'IR' => esc_html__('Iran', 'baskerville'),
			'IQ' => esc_html__('Iraq', 'baskerville'),
			'IE' => esc_html__('Ireland', 'baskerville'),
			'IL' => esc_html__('Israel', 'baskerville'),
			'IT' => esc_html__('Italy', 'baskerville'),
			'JM' => esc_html__('Jamaica', 'baskerville'),
			'JP' => esc_html__('Japan', 'baskerville'),
			'JO' => esc_html__('Jordan', 'baskerville'),
			'KZ' => esc_html__('Kazakhstan', 'baskerville'),
			'KE' => esc_html__('Kenya', 'baskerville'),
			'KI' => esc_html__('Kiribati', 'baskerville'),
			'KP' => esc_html__('North Korea', 'baskerville'),
			'KR' => esc_html__('South Korea', 'baskerville'),
			'KW' => esc_html__('Kuwait', 'baskerville'),
			'KG' => esc_html__('Kyrgyzstan', 'baskerville'),
			'LA' => esc_html__('Laos', 'baskerville'),
			'LV' => esc_html__('Latvia', 'baskerville'),
			'LB' => esc_html__('Lebanon', 'baskerville'),
			'LS' => esc_html__('Lesotho', 'baskerville'),
			'LR' => esc_html__('Liberia', 'baskerville'),
			'LY' => esc_html__('Libya', 'baskerville'),
			'LI' => esc_html__('Liechtenstein', 'baskerville'),
			'LT' => esc_html__('Lithuania', 'baskerville'),
			'LU' => esc_html__('Luxembourg', 'baskerville'),
			'MO' => esc_html__('Macau', 'baskerville'),
			'MK' => esc_html__('North Macedonia', 'baskerville'),
			'MG' => esc_html__('Madagascar', 'baskerville'),
			'MW' => esc_html__('Malawi', 'baskerville'),
			'MY' => esc_html__('Malaysia', 'baskerville'),
			'MV' => esc_html__('Maldives', 'baskerville'),
			'ML' => esc_html__('Mali', 'baskerville'),
			'MT' => esc_html__('Malta', 'baskerville'),
			'MH' => esc_html__('Marshall Islands', 'baskerville'),
			'MQ' => esc_html__('Martinique', 'baskerville'),
			'MR' => esc_html__('Mauritania', 'baskerville'),
			'MU' => esc_html__('Mauritius', 'baskerville'),
			'YT' => esc_html__('Mayotte', 'baskerville'),
			'MX' => esc_html__('Mexico', 'baskerville'),
			'FM' => esc_html__('Micronesia', 'baskerville'),
			'MD' => esc_html__('Moldova', 'baskerville'),
			'MC' => esc_html__('Monaco', 'baskerville'),
			'MN' => esc_html__('Mongolia', 'baskerville'),
			'ME' => esc_html__('Montenegro', 'baskerville'),
			'MS' => esc_html__('Montserrat', 'baskerville'),
			'MA' => esc_html__('Morocco', 'baskerville'),
			'MZ' => esc_html__('Mozambique', 'baskerville'),
			'MM' => esc_html__('Myanmar', 'baskerville'),
			'NA' => esc_html__('Namibia', 'baskerville'),
			'NR' => esc_html__('Nauru', 'baskerville'),
			'NP' => esc_html__('Nepal', 'baskerville'),
			'NL' => esc_html__('Netherlands', 'baskerville'),
			'NC' => esc_html__('New Caledonia', 'baskerville'),
			'NZ' => esc_html__('New Zealand', 'baskerville'),
			'NI' => esc_html__('Nicaragua', 'baskerville'),
			'NE' => esc_html__('Niger', 'baskerville'),
			'NG' => esc_html__('Nigeria', 'baskerville'),
			'NU' => esc_html__('Niue', 'baskerville'),
			'NF' => esc_html__('Norfolk Island', 'baskerville'),
			'MP' => esc_html__('Northern Mariana Islands', 'baskerville'),
			'NO' => esc_html__('Norway', 'baskerville'),
			'OM' => esc_html__('Oman', 'baskerville'),
			'PK' => esc_html__('Pakistan', 'baskerville'),
			'PW' => esc_html__('Palau', 'baskerville'),
			'PS' => esc_html__('Palestine', 'baskerville'),
			'PA' => esc_html__('Panama', 'baskerville'),
			'PG' => esc_html__('Papua New Guinea', 'baskerville'),
			'PY' => esc_html__('Paraguay', 'baskerville'),
			'PE' => esc_html__('Peru', 'baskerville'),
			'PH' => esc_html__('Philippines', 'baskerville'),
			'PL' => esc_html__('Poland', 'baskerville'),
			'PT' => esc_html__('Portugal', 'baskerville'),
			'PR' => esc_html__('Puerto Rico', 'baskerville'),
			'QA' => esc_html__('Qatar', 'baskerville'),
			'RE' => esc_html__('Réunion', 'baskerville'),
			'RO' => esc_html__('Romania', 'baskerville'),
			'RU' => esc_html__('Russia', 'baskerville'),
			'RW' => esc_html__('Rwanda', 'baskerville'),
			'WS' => esc_html__('Samoa', 'baskerville'),
			'SM' => esc_html__('San Marino', 'baskerville'),
			'ST' => esc_html__('São Tomé and Príncipe', 'baskerville'),
			'SA' => esc_html__('Saudi Arabia', 'baskerville'),
			'SN' => esc_html__('Senegal', 'baskerville'),
			'RS' => esc_html__('Serbia', 'baskerville'),
			'SC' => esc_html__('Seychelles', 'baskerville'),
			'SL' => esc_html__('Sierra Leone', 'baskerville'),
			'SG' => esc_html__('Singapore', 'baskerville'),
			'SK' => esc_html__('Slovakia', 'baskerville'),
			'SI' => esc_html__('Slovenia', 'baskerville'),
			'SB' => esc_html__('Solomon Islands', 'baskerville'),
			'SO' => esc_html__('Somalia', 'baskerville'),
			'ZA' => esc_html__('South Africa', 'baskerville'),
			'SS' => esc_html__('South Sudan', 'baskerville'),
			'ES' => esc_html__('Spain', 'baskerville'),
			'LK' => esc_html__('Sri Lanka', 'baskerville'),
			'SD' => esc_html__('Sudan', 'baskerville'),
			'SR' => esc_html__('Suriname', 'baskerville'),
			'SZ' => esc_html__('Eswatini', 'baskerville'),
			'SE' => esc_html__('Sweden', 'baskerville'),
			'CH' => esc_html__('Switzerland', 'baskerville'),
			'SY' => esc_html__('Syria', 'baskerville'),
			'TW' => esc_html__('Taiwan', 'baskerville'),
			'TJ' => esc_html__('Tajikistan', 'baskerville'),
			'TZ' => esc_html__('Tanzania', 'baskerville'),
			'TH' => esc_html__('Thailand', 'baskerville'),
			'TL' => esc_html__('Timor-Leste', 'baskerville'),
			'TG' => esc_html__('Togo', 'baskerville'),
			'TK' => esc_html__('Tokelau', 'baskerville'),
			'TO' => esc_html__('Tonga', 'baskerville'),
			'TT' => esc_html__('Trinidad and Tobago', 'baskerville'),
			'TN' => esc_html__('Tunisia', 'baskerville'),
			'TR' => esc_html__('Turkey', 'baskerville'),
			'TM' => esc_html__('Turkmenistan', 'baskerville'),
			'TC' => esc_html__('Turks and Caicos Islands', 'baskerville'),
			'TV' => esc_html__('Tuvalu', 'baskerville'),
			'UG' => esc_html__('Uganda', 'baskerville'),
			'UA' => esc_html__('Ukraine', 'baskerville'),
			'AE' => esc_html__('United Arab Emirates', 'baskerville'),
			'GB' => esc_html__('United Kingdom', 'baskerville'),
			'US' => esc_html__('United States', 'baskerville'),
			'UY' => esc_html__('Uruguay', 'baskerville'),
			'UZ' => esc_html__('Uzbekistan', 'baskerville'),
			'VU' => esc_html__('Vanuatu', 'baskerville'),
			'VA' => esc_html__('Vatican City', 'baskerville'),
			'VE' => esc_html__('Venezuela', 'baskerville'),
			'VN' => esc_html__('Vietnam', 'baskerville'),
			'VG' => esc_html__('British Virgin Islands', 'baskerville'),
			'VI' => esc_html__('U.S. Virgin Islands', 'baskerville'),
			'WF' => esc_html__('Wallis and Futuna', 'baskerville'),
			'YE' => esc_html__('Yemen', 'baskerville'),
			'ZM' => esc_html__('Zambia', 'baskerville'),
			'ZW' => esc_html__('Zimbabwe', 'baskerville'),
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
			$title = esc_html__('Allow List Mode Active', 'baskerville');
			$description = sprintf(
				/* translators: %1$d is the number of countries, %2$s is either 'country' or 'countries', %3$s is the list of country names */
				esc_html__('Access is allowed ONLY from %1$d %2$s: %3$s', 'baskerville'),
				esc_html( $country_count ),
				$country_count === 1 ? esc_html__('country', 'baskerville') : esc_html__('countries', 'baskerville'),
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
			$title = esc_html__('Block List Mode Active', 'baskerville');
			$description = sprintf(
				/* translators: %1$d is the number of countries, %2$s is either 'country' or 'countries', %3$s is the list of country names */
				esc_html__('Access is blocked from %1$d %2$s: %3$s', 'baskerville'),
				esc_html( $country_count ),
				$country_count === 1 ? esc_html__('country', 'baskerville') : esc_html__('countries', 'baskerville'),
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
				$country_name = esc_html__('Unknown', 'baskerville');
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
		$base_url = admin_url('options-general.php?page=baskerville-settings&tab=country-control');

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
					<h3><?php esc_html_e('Traffic by Country', 'baskerville'); ?></h3>
					<table>
						<thead>
							<tr>
								<th><?php esc_html_e('Country', 'baskerville'); ?></th>
								<th><?php esc_html_e('Total Requests', 'baskerville'); ?></th>
								<th><?php esc_html_e('Blocked (403)', 'baskerville'); ?></th>
								<th><?php esc_html_e('Block Rate', 'baskerville'); ?></th>
								<th><?php esc_html_e('Access Status', 'baskerville'); ?></th>
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
									$status_label = __('Unknown', 'baskerville');
									$status_color = '#999';
									$status_icon = '❓';
								} elseif ($geoip_mode === 'allow_all') {
									$access_allowed = true;
									$status_label = __('Allowed', 'baskerville');
									$status_color = '#4CAF50';
									$status_icon = '✅';
								} elseif ($geoip_mode === 'blacklist') {
									$is_in_blacklist = in_array($stat['code'], $blacklist_countries);
									$access_allowed = !$is_in_blacklist;
									if ($is_in_blacklist) {
										$status_label = __('Blocked (Block List)', 'baskerville');
										$status_color = '#d32f2f';
										$status_icon = '🚫';
									} else {
										$status_label = __('Allowed', 'baskerville');
										$status_color = '#4CAF50';
										$status_icon = '✅';
									}
								} elseif ($geoip_mode === 'whitelist') {
									$is_in_whitelist = in_array($stat['code'], $whitelist_countries);
									$access_allowed = $is_in_whitelist;
									if ($is_in_whitelist) {
										$status_label = __('Allowed (Allow List)', 'baskerville');
										$status_color = '#4CAF50';
										$status_icon = '✅';
									} else {
										$status_label = __('Blocked', 'baskerville');
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
					<p><?php esc_html_e('No traffic data available for the selected period.', 'baskerville'); ?></p>
				</div>
			<?php endif; ?>
		</div>

		<?php if (!empty($country_stats)): ?>
		<script>
		(function waitForChart() {
			if (typeof Chart === 'undefined') {
				setTimeout(waitForChart, 100);
				return;
			}

			const countryStats = <?php echo wp_json_encode($country_stats); ?>;
			const hours = <?php echo absint($hours); ?>;

			// Prepare data - limit to top 15 countries
			const topCountries = countryStats.slice(0, 15);
			const labels = topCountries.map(c => c.name + ' (' + c.code + ')');
			const totalData = topCountries.map(c => c.total);
			const blockedData = topCountries.map(c => c.blocked);

			// Color palette (same as Human vs Automated)
			const colors = [
				'#4CAF50', '#2196F3', '#FF9800', '#9C27B0', '#F44336',
				'#00BCD4', '#FFEB3B', '#795548', '#607D8B', '#E91E63',
				'#3F51B5', '#8BC34A', '#FF5722', '#009688', '#FFC107'
			];

			// 1) Total Traffic by Country
			const trafficCtx = document.getElementById('baskervilleCountryTrafficChart').getContext('2d');
			new Chart(trafficCtx, {
				type: 'bar',
				data: {
					labels,
					datasets: [{
						label: '<?php echo esc_js( esc_html__( 'Total Requests', 'baskerville' ) ); ?>',
						data: totalData,
						backgroundColor: colors
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: true,
					indexAxis: 'y',
					plugins: {
						title: {
							display: true,
							text: '<?php echo esc_js( esc_html__( 'Traffic by Country — last', 'baskerville' ) ); ?> ' + hours + 'h',
							font: { size: 16, weight: 'bold' }
						},
						legend: { display: false }
					},
					scales: {
						x: {
							beginAtZero: true,
							title: { display: true, text: '<?php echo esc_js( esc_html__( 'Requests', 'baskerville' ) ); ?>' }
						}
					}
				}
			});

			// 2) 403 Bans by Country
			const bansCtx = document.getElementById('baskervilleCountryBansChart').getContext('2d');
			new Chart(bansCtx, {
				type: 'bar',
				data: {
					labels,
					datasets: [{
						label: '<?php echo esc_js( esc_html__( '403 Blocked', 'baskerville' ) ); ?>',
						data: blockedData,
						backgroundColor: '#d32f2f'
					}]
				},
				options: {
					responsive: true,
					maintainAspectRatio: true,
					indexAxis: 'y',
					plugins: {
						title: {
							display: true,
							text: '<?php echo esc_js( esc_html__( '403 Bans by Country — last', 'baskerville' ) ); ?> ' + hours + 'h',
							font: { size: 16, weight: 'bold' }
						},
						legend: { display: false }
					},
					scales: {
						x: {
							beginAtZero: true,
							title: { display: true, text: '<?php echo esc_js( esc_html__( 'Blocked Requests', 'baskerville' ) ); ?>' }
						}
					}
				}
			});
		})();
		</script>
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
		$base_url = admin_url('options-general.php?page=baskerville-settings&tab=overview');
		?>

		<!-- Real-time Live Dashboard -->
		<div class="baskerville-live-dashboard">
			<h2 class="baskerville-dashboard-header">
				<span class="dashicons dashicons-visibility" ></span>
				<?php esc_html_e('Live Bot Attack Dashboard', 'baskerville'); ?>
				<span class="live-indicator"></span>
			</h2>

			<!-- Live Stats Cards -->
			<div class="live-stats-grid">
				<div class="live-stat-card baskerville-gradient-purple">
					<div class="stat-icon">🛡️</div>
					<div class="stat-value" id="blocks-today">...</div>
					<div class="stat-label"><?php esc_html_e('Blocked Today', 'baskerville'); ?></div>
				</div>

				<div class="live-stat-card baskerville-gradient-pink">
					<div class="stat-icon">⚡</div>
					<div class="stat-value" id="blocks-hour">...</div>
					<div class="stat-label"><?php esc_html_e('Blocked Last Hour', 'baskerville'); ?></div>
				</div>

				<div class="live-stat-card baskerville-gradient-blue">
					<div class="stat-icon">🌍</div>
					<div class="stat-value" id="top-country">...</div>
					<div class="stat-label"><?php esc_html_e('Top Country Blocked', 'baskerville'); ?></div>
				</div>
			</div>

			<!-- Live Feed -->
			<div class="live-feed-container">
				<div class="live-feed">
				<h3 class="baskerville-heading-flex">
						<span class="dashicons dashicons-admin-site"></span>
						<?php esc_html_e('Live Feed', 'baskerville'); ?>
						<span class="feed-header-info"><?php esc_html_e('Auto-refresh: 10s', 'baskerville'); ?></span>
					</h3>
					<div id="live-feed-items" class="baskerville-font-sm">
						<div class="baskerville-loading">
							<span class="dashicons dashicons-update baskerville-loading-spinner"></span>
							<p><?php esc_html_e('Loading live data...', 'baskerville'); ?></p>
						</div>
					</div>
				</div>

				<div class="top-attackers">
					<h3 class="baskerville-heading-flex">
						<span class="dashicons dashicons-warning"></span>
						<?php esc_html_e('Top Attackers', 'baskerville'); ?>
					</h3>
					<div id="top-attackers-list" class="baskerville-font-sm">
						<div class="baskerville-loading">
							<?php esc_html_e('Loading...', 'baskerville'); ?>
						</div>
					</div>
				</div>
			</div>
		</div>

		<script>
		jQuery(document).ready(function($) {
			let lastEventId = null;

			function updateLiveFeed() {
				$.ajax({
					url: ajaxurl,
					type: 'POST',
					data: { action: 'baskerville_get_live_feed' },
					success: function(response) {
						if (response.success && response.data) {
							// Debug: check first event timestamp
							if (response.data.length > 0) {
								console.log('First event created_at:', response.data[0].created_at);
								console.log('Current time:', new Date());
								console.log('Event time parsed:', new Date(response.data[0].created_at));
							}
							renderLiveFeed(response.data);
						}
					}
				});
			}

			function updateLiveStats() {
				$.ajax({
					url: ajaxurl,
					type: 'POST',
					data: { action: 'baskerville_get_live_stats' },
					success: function(response) {
						if (response.success && response.data) {
							$('#blocks-today').text(response.data.blocks_today.toLocaleString());
							$('#blocks-hour').text(response.data.blocks_hour.toLocaleString());

							if (response.data.top_countries && response.data.top_countries.length > 0) {
								$('#top-country').text(response.data.top_countries[0].country_name || response.data.top_countries[0].country_code || 'N/A');
							}

							renderTopAttackers(response.data.top_ips);
						}
					}
				});
			}

			function renderLiveFeed(events) {
				const container = $('#live-feed-items');
				container.empty();

				if (!events || events.length === 0) {
					container.html('<div class="baskerville-no-data"><?php echo esc_js( esc_html__( 'No recent events', 'baskerville' ) ); ?></div>');
					return;
				}

				events.forEach(function(event) {
					const icon = getEventIcon(event.classification, event.event_type);
					const color = getEventColor(event.classification, event.event_type);
					const timeAgo = getTimeAgo(event.created_at);

					// Special handling for Turnstile failed challenge
					const isTurnstileFail = event.event_type === 'ts_fail';
					const displayLabel = isTurnstileFail ? '<?php echo esc_js( __( 'TURNSTILE FAILED', 'baskerville' ) ); ?>' : event.classification.toUpperCase().replace('_', ' ');

					let banBadge = '';
					if (isTurnstileFail) {
						banBadge = '<span class="baskerville-badge baskerville-badge-challenge-failed"><?php echo esc_js( __( 'CHALLENGE FAILED', 'baskerville' ) ); ?></span>';
					} else if (event.is_banned) {
						banBadge = '<span class="baskerville-badge baskerville-badge-banned"><?php echo esc_js( __( 'BANNED', 'baskerville' ) ); ?></span>';
					} else {
						banBadge = '<span class="baskerville-badge baskerville-badge-detected"><?php echo esc_js( __( 'DETECTED', 'baskerville' ) ); ?></span>';
					}

					// Extract company name from reason or block_reason for AI bots
					let companyBadge = '';
					if (event.classification === 'ai_bot') {
						// Try to extract company name from reason (format: "AI bot detected by user agent (CompanyName)" or "Honeypot triggered: accessed hidden link (CompanyName)")
						let companyName = null;
						const reasonMatch = event.reason && event.reason.match(/\(([^)]+)\)$/);
						if (reasonMatch) {
							companyName = reasonMatch[1];
						}
						// Also check block_reason for blocked bots (format: "ai-bot-block-all:CompanyName")
						if (!companyName && event.block_reason) {
							const blockMatch = event.block_reason.match(/:([^:]+)$/);
							if (blockMatch) {
								companyName = blockMatch[1];
							}
						}
						if (companyName) {
							companyBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-company">' + companyName + '</span>';
						} else if (event.event_type === 'honeypot') {
							// For honeypot without identified company, show "Unknown Bot"
							companyBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-unknown"><?php echo esc_js( __( 'Unknown Bot', 'baskerville' ) ); ?></span>';
						}
					}

					// Detection method badge and User-Agent info
					let detectionBadge = '';
					let userAgentInfo = '';

					// Check if detection was based on User-Agent
					const isUserAgentBased = event.reason && (
						event.reason.toLowerCase().includes('user agent') ||
						event.reason.toLowerCase().includes('user-agent')
					);

					if (isTurnstileFail) {
						detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-turnstile">🛡️ <?php echo esc_js( __( 'TURNSTILE', 'baskerville' ) ); ?></span>';
						// Show User-Agent for turnstile failures
						if (event.ua) {
							const truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
							userAgentInfo = '<br><span class="baskerville-feed-ua"><?php echo esc_js( __( 'UA:', 'baskerville' ) ); ?> ' + truncatedUA + '</span>';
						}
					} else if (event.classification === 'ai_bot') {
						if (event.event_type === 'honeypot') {
							detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-honeypot">🍯 <?php echo esc_js( __( 'HONEYPOT', 'baskerville' ) ); ?></span>';
							// Show User-Agent for honeypot too
							if (event.ua) {
								const truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
								userAgentInfo = '<br><span class="baskerville-feed-ua"><?php echo esc_js( __( 'UA:', 'baskerville' ) ); ?> ' + truncatedUA + '</span>';
							}
						} else {
							detectionBadge = '<span class="baskerville-badge baskerville-badge-sm baskerville-badge-useragent"><?php echo esc_js( __( 'USER-AGENT', 'baskerville' ) ); ?></span>';
							// Show User-Agent for UA-based detection
							if (event.ua) {
								const truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
								userAgentInfo = '<br><span class="baskerville-feed-ua"><?php echo esc_js( __( 'UA:', 'baskerville' ) ); ?> ' + truncatedUA + '</span>';
							}
						}
					} else {
						// Show User-Agent for other bot types if UA-based detection
						if (isUserAgentBased && event.ua) {
							const truncatedUA = event.ua.length > 100 ? event.ua.substring(0, 100) + '...' : event.ua;
							userAgentInfo = '<br><span class="baskerville-feed-ua"><?php echo esc_js( __( 'UA:', 'baskerville' ) ); ?> ' + truncatedUA + '</span>';
						}
					}

					const item = $('<div class="live-feed-item"></div>');
					const countryName = event.country_code ? getCountryName(event.country_code) : '';
					const reasonText = isTurnstileFail ? '<?php echo esc_js( __( 'Failed Cloudflare Turnstile challenge', 'baskerville' ) ); ?>' : (event.reason || '<?php echo esc_js( __( 'No reason', 'baskerville' ) ); ?>');
					item.html(
						'<span class="feed-icon">' + icon + '</span> ' +
						'<strong style="color: ' + color + ';">' + displayLabel + '</strong>' +
						detectionBadge + companyBadge + ' ' +
						event.ip + ' ' +
						(countryName ? '<span class="baskerville-feed-country">' + countryName + '</span> ' : '') +
						banBadge +
						'<span class="baskerville-feed-time">' + timeAgo + '</span><br>' +
						'<span class="baskerville-feed-score">' +
						reasonText +
						(event.score ? ' (<?php echo esc_js( __( 'score', 'baskerville' ) ); ?>: ' + event.score + ')' : '') +
						(event.block_reason ? ' | <?php echo esc_js( __( 'Ban reason', 'baskerville' ) ); ?>: ' + event.block_reason : '') +
						'</span>' +
						userAgentInfo
					);
					container.append(item);
				});
			}

			function renderTopAttackers(ips) {
				const container = $('#top-attackers-list');
				container.empty();

				if (!ips || ips.length === 0) {
					container.html('<div class="baskerville-no-data"><?php echo esc_js( esc_html__( 'No data', 'baskerville' ) ); ?></div>');
					return;
				}

				ips.forEach(function(item, index) {
					const badge = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : (index + 1) + '.';
					container.append(
						'<div class="baskerville-attacker-item">' +
						'<strong>' + badge + '</strong> ' +
						item.ip + ' ' +
						(item.country_code ? '<span class="baskerville-feed-country">' + item.country_code + '</span>' : '') +
						'<br><span class="baskerville-attacker-count">' + item.count + ' <?php echo esc_js( __( 'attempts', 'baskerville' ) ); ?></span>' +
						'</div>'
					);
				});
			}

			function getEventIcon(classification, eventType) {
				if (eventType === 'ts_fail') return '🛡️';
				if (eventType === 'honeypot') return '🍯';
				if (classification === 'ai_bot') return '🤖';
				if (classification === 'bad_bot') return '🔴';
				if (classification === 'bot') return '🟡';
				return '⚠️';
			}

			function getEventColor(classification, eventType) {
				if (eventType === 'ts_fail') return '#dc2626';
				if (classification === 'ai_bot') return '#9333ea';
				if (classification === 'bad_bot') return '#dc2626';
				if (classification === 'bot') return '#f59e0b';
				return '#6b7280';
			}

			function getTimeAgo(timestamp) {
				const now = new Date();
				const eventTime = new Date(timestamp);
				const seconds = Math.floor((now - eventTime) / 1000);

				if (seconds < 60) return seconds + 's ago';
				if (seconds < 3600) return Math.floor(seconds / 60) + 'm ago';
				if (seconds < 86400) return Math.floor(seconds / 3600) + 'h ago';
				return Math.floor(seconds / 86400) + 'd ago';
			}

			function getCountryName(code) {
				const countries = {
					'AF': 'Afghanistan', 'AL': 'Albania', 'DZ': 'Algeria', 'AS': 'American Samoa', 'AD': 'Andorra',
					'AO': 'Angola', 'AI': 'Anguilla', 'AQ': 'Antarctica', 'AG': 'Antigua and Barbuda', 'AR': 'Argentina',
					'AM': 'Armenia', 'AW': 'Aruba', 'AU': 'Australia', 'AT': 'Austria', 'AZ': 'Azerbaijan',
					'BS': 'Bahamas', 'BH': 'Bahrain', 'BD': 'Bangladesh', 'BB': 'Barbados', 'BY': 'Belarus',
					'BE': 'Belgium', 'BZ': 'Belize', 'BJ': 'Benin', 'BM': 'Bermuda', 'BT': 'Bhutan',
					'BO': 'Bolivia', 'BA': 'Bosnia and Herzegovina', 'BW': 'Botswana', 'BR': 'Brazil', 'BN': 'Brunei',
					'BG': 'Bulgaria', 'BF': 'Burkina Faso', 'BI': 'Burundi', 'KH': 'Cambodia', 'CM': 'Cameroon',
					'CA': 'Canada', 'CV': 'Cape Verde', 'KY': 'Cayman Islands', 'CF': 'Central African Republic', 'TD': 'Chad',
					'CL': 'Chile', 'CN': 'China', 'CO': 'Colombia', 'KM': 'Comoros', 'CG': 'Congo',
					'CD': 'Congo (DRC)', 'CK': 'Cook Islands', 'CR': 'Costa Rica', 'CI': 'Ivory Coast', 'HR': 'Croatia',
					'CU': 'Cuba', 'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DK': 'Denmark', 'DJ': 'Djibouti',
					'DM': 'Dominica', 'DO': 'Dominican Republic', 'EC': 'Ecuador', 'EG': 'Egypt', 'SV': 'El Salvador',
					'GQ': 'Equatorial Guinea', 'ER': 'Eritrea', 'EE': 'Estonia', 'ET': 'Ethiopia', 'FJ': 'Fiji',
					'FI': 'Finland', 'FR': 'France', 'GA': 'Gabon', 'GM': 'Gambia', 'GE': 'Georgia',
					'DE': 'Germany', 'GH': 'Ghana', 'GI': 'Gibraltar', 'GR': 'Greece', 'GL': 'Greenland',
					'GD': 'Grenada', 'GU': 'Guam', 'GT': 'Guatemala', 'GN': 'Guinea', 'GW': 'Guinea-Bissau',
					'GY': 'Guyana', 'HT': 'Haiti', 'HN': 'Honduras', 'HK': 'Hong Kong', 'HU': 'Hungary',
					'IS': 'Iceland', 'IN': 'India', 'ID': 'Indonesia', 'IR': 'Iran', 'IQ': 'Iraq',
					'IE': 'Ireland', 'IL': 'Israel', 'IT': 'Italy', 'JM': 'Jamaica', 'JP': 'Japan',
					'JO': 'Jordan', 'KZ': 'Kazakhstan', 'KE': 'Kenya', 'KI': 'Kiribati', 'KP': 'North Korea',
					'KR': 'South Korea', 'KW': 'Kuwait', 'KG': 'Kyrgyzstan', 'LA': 'Laos', 'LV': 'Latvia',
					'LB': 'Lebanon', 'LS': 'Lesotho', 'LR': 'Liberia', 'LY': 'Libya', 'LI': 'Liechtenstein',
					'LT': 'Lithuania', 'LU': 'Luxembourg', 'MO': 'Macau', 'MK': 'North Macedonia', 'MG': 'Madagascar',
					'MW': 'Malawi', 'MY': 'Malaysia', 'MV': 'Maldives', 'ML': 'Mali', 'MT': 'Malta',
					'MH': 'Marshall Islands', 'MR': 'Mauritania', 'MU': 'Mauritius', 'MX': 'Mexico', 'FM': 'Micronesia',
					'MD': 'Moldova', 'MC': 'Monaco', 'MN': 'Mongolia', 'ME': 'Montenegro', 'MA': 'Morocco',
					'MZ': 'Mozambique', 'MM': 'Myanmar', 'NA': 'Namibia', 'NR': 'Nauru', 'NP': 'Nepal',
					'NL': 'Netherlands', 'NZ': 'New Zealand', 'NI': 'Nicaragua', 'NE': 'Niger', 'NG': 'Nigeria',
					'NO': 'Norway', 'OM': 'Oman', 'PK': 'Pakistan', 'PW': 'Palau', 'PS': 'Palestine',
					'PA': 'Panama', 'PG': 'Papua New Guinea', 'PY': 'Paraguay', 'PE': 'Peru', 'PH': 'Philippines',
					'PL': 'Poland', 'PT': 'Portugal', 'PR': 'Puerto Rico', 'QA': 'Qatar', 'RO': 'Romania',
					'RU': 'Russia', 'RW': 'Rwanda', 'WS': 'Samoa', 'SM': 'San Marino', 'SA': 'Saudi Arabia',
					'SN': 'Senegal', 'RS': 'Serbia', 'SC': 'Seychelles', 'SL': 'Sierra Leone', 'SG': 'Singapore',
					'SK': 'Slovakia', 'SI': 'Slovenia', 'SB': 'Solomon Islands', 'SO': 'Somalia', 'ZA': 'South Africa',
					'SS': 'South Sudan', 'ES': 'Spain', 'LK': 'Sri Lanka', 'SD': 'Sudan', 'SR': 'Suriname',
					'SZ': 'Eswatini', 'SE': 'Sweden', 'CH': 'Switzerland', 'SY': 'Syria', 'TW': 'Taiwan',
					'TJ': 'Tajikistan', 'TZ': 'Tanzania', 'TH': 'Thailand', 'TL': 'Timor-Leste', 'TG': 'Togo',
					'TO': 'Tonga', 'TT': 'Trinidad and Tobago', 'TN': 'Tunisia', 'TR': 'Turkey', 'TM': 'Turkmenistan',
					'TV': 'Tuvalu', 'UG': 'Uganda', 'UA': 'Ukraine', 'AE': 'UAE', 'GB': 'United Kingdom',
					'US': 'United States', 'UY': 'Uruguay', 'UZ': 'Uzbekistan', 'VU': 'Vanuatu', 'VA': 'Vatican City',
					'VE': 'Venezuela', 'VN': 'Vietnam', 'YE': 'Yemen', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'
				};
				return countries[code] || code;
			}

			// Initial load
			updateLiveFeed();
			updateLiveStats();

			// Auto-refresh every 10 seconds
			setInterval(updateLiveFeed, 10000);
			setInterval(updateLiveStats, 10000);
		});
		</script>

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
					<div class="stat-label"><?php esc_html_e('Total Visits', 'baskerville'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-dark-grey">
					<div class="stat-value"><?php echo number_format($stats['total_ips']); ?></div>
					<div class="stat-label"><?php esc_html_e('Total IPs', 'baskerville'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-red">
					<div class="stat-value"><?php echo number_format($stats['blocked_ips']); ?></div>
					<div class="stat-label"><?php esc_html_e('IPs Blocked', 'baskerville'); ?></div>
				</div>
				<div class="baskerville-stat-card stat-red">
					<div class="stat-value"><?php echo esc_html($stats['block_rate']); ?>%</div>
					<div class="stat-label"><?php esc_html_e('Block Rate', 'baskerville'); ?></div>
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
					<?php esc_html_e('Logging Status', 'baskerville'); ?>
				</h3>
				<p>
					<strong><?php esc_html_e('Mode:', 'baskerville'); ?></strong> <?php esc_html_e( 'Direct to Database', 'baskerville' ); ?><br>
					<span class="baskerville-text-success">✓</span> <?php esc_html_e( 'Logs are written directly to the database. No import needed, charts update in real-time.', 'baskerville' ); ?><br>
					<br>
					💡 <strong><?php esc_html_e( 'Note:', 'baskerville' ); ?></strong> <?php esc_html_e( 'This mode is slower (~500ms per request) but ensures data is always up-to-date. Consider switching to "File logging" mode for better performance on high-traffic sites.', 'baskerville' ); ?>
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
					$cron_message = '⚠️ ' . esc_html__( 'Auto-import not scheduled!', 'baskerville' );
				} elseif ($wp_cron_disabled) {
					$cron_health = 'warning';
					$cron_message = '⚠️ ' . esc_html__( 'WP-Cron is disabled (DISABLE_WP_CRON=true). You must set up a real cron job.', 'baskerville' );
				} elseif ($pending_files > 5) {
					$cron_health = 'warning';
					$cron_message = '⚠️ ' . esc_html__( 'Many pending files - cron might not be running frequently.', 'baskerville' );
				}
			?>
			<div class="notice notice-<?php echo $cron_health === 'good' ? 'info' : ($cron_health === 'error' ? 'error' : 'warning'); ?> inline baskerville-notice">
				<h3 class="baskerville-section-title">
					<span class="dashicons dashicons-database-import"></span>
					<?php esc_html_e('Log File Import Status', 'baskerville'); ?>
				</h3>
				<table class="baskerville-simple-table">
					<tr>
						<td><strong><?php esc_html_e('Logging Mode:', 'baskerville'); ?></strong></td>
						<td class="baskerville-td-padded">File logging (for performance)</td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Pending log files:', 'baskerville'); ?></strong></td>
						<td class="baskerville-td-padded"><?php echo esc_html($pending_files); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Last import:', 'baskerville'); ?></strong></td>
						<td class="baskerville-td-padded"><?php echo esc_html($last_import_time); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('WP-Cron status:', 'baskerville'); ?></strong></td>
						<td class="baskerville-td-padded">
							<?php if ($wp_cron_disabled): ?>
								<span class="baskerville-text-danger">❌ Disabled (DISABLE_WP_CRON=true)</span>
							<?php else: ?>
								<span class="baskerville-text-success">✓ Enabled</span>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ($next_cron): ?>
					<tr>
						<td><strong><?php esc_html_e('Next auto-import:', 'baskerville'); ?></strong></td>
						<td class="baskerville-td-padded"><?php echo esc_html(human_time_diff($next_cron, time())); ?> from now</td>
					</tr>
					<?php endif; ?>
				</table>

				<?php if ($cron_message): ?>
					<div class="baskerville-warning-box <?php echo $cron_health === 'error' ? 'baskerville-warning-box-pink' : 'baskerville-warning-box-yellow'; ?>">
						<?php echo esc_html($cron_message); ?>
						<?php if ($wp_cron_disabled): ?>
							<br><br>
							<strong>Fix:</strong> Add this to your server crontab:<br>
							<code class="baskerville-code">
								* * * * * wget -q -O - <?php echo esc_url(site_url('wp-cron.php?doing_wp_cron')); ?> &>/dev/null || curl -s <?php echo esc_url(site_url('wp-cron.php?doing_wp_cron')); ?> &>/dev/null
							</code>
						<?php endif; ?>
					</div>
				<?php endif; ?>

				<button type="button" class="button button-primary" id="import-logs-now">
					<?php esc_html_e('Import Logs Now', 'baskerville'); ?>
				</button>
				<span id="import-logs-result" class="baskerville-ml-10"></span>

				<p class="baskerville-mt-15 baskerville-font-xs">
					💡 <strong><?php esc_html_e( 'Tip:', 'baskerville' ); ?></strong> <?php esc_html_e( 'Auto-import runs every minute. If you have many visitors, consider switching to "Direct to Database" mode in Settings (slower but no import delay).', 'baskerville' ); ?>
				</p>
			</div>
			<?php elseif ($log_mode === 'disabled'): ?>
			<div class="notice notice-warning inline baskerville-notice">
				<h3 class="baskerville-section-title">
					<span class="dashicons dashicons-warning"></span>
					<?php esc_html_e('Logging Status', 'baskerville'); ?>
				</h3>
				<p>
					<strong><?php esc_html_e('Mode:', 'baskerville'); ?></strong> <?php esc_html_e( 'Disabled', 'baskerville'); ?><br>
					<span class="baskerville-text-danger">⚠️</span> <?php esc_html_e( 'Logging is completely disabled. No statistics or charts will be available.', 'baskerville'); ?><br>
					<br>
					💡 <?php esc_html_e( 'Go to Settings tab to enable logging (either "File logging" or "Direct to Database").', 'baskerville'); ?>
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
			error_log('Baskerville AI Bots Tab Error: ' . $e->getMessage());
			error_log('Baskerville AI Bots Tab Trace: ' . $e->getTraceAsString());
			?>
			<div class="notice notice-error">
				<p><strong>Error loading AI bots data:</strong></p>
				<p><?php echo esc_html($e->getMessage()); ?></p>
				<pre class="baskerville-pre"><?php echo esc_html($e->getTraceAsString()); ?></pre>
			</div>
			<?php
			return;
		} catch (Error $e) {
			error_log('Baskerville AI Bots Tab Fatal Error: ' . $e->getMessage());
			error_log('Baskerville AI Bots Tab Trace: ' . $e->getTraceAsString());
			?>
			<div class="notice notice-error">
				<p><strong>Fatal error loading AI bots data:</strong></p>
				<p><?php echo esc_html($e->getMessage()); ?></p>
				<pre class="baskerville-pre"><?php echo esc_html($e->getTraceAsString()); ?></pre>
			</div>
			<?php
			return;
		}

		// Build URLs for period buttons
		$base_url = admin_url('options-general.php?page=baskerville-settings&tab=ai-bot-control');

		// Check if we have any data
		$has_data = !empty($data['companies']) && count($data['companies']) > 0;
		?>

		<div class="baskerville-ai-bots-dashboard">
			<h2 class="baskerville-dashboard-header">
				<span class="dashicons dashicons-chart-bar" ></span>
				<?php esc_html_e('AI Bots Activity', 'baskerville'); ?>
			</h2>

			<!-- Period Selection Buttons -->
			<div class="period-buttons">
				<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
				   class="button <?php echo $period === '12h' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('12h', 'baskerville'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
				   class="button <?php echo $period === '1day' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('1 day', 'baskerville'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
				   class="button <?php echo $period === '3days' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('3 days', 'baskerville'); ?>
				</a>
				<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
				   class="button <?php echo $period === '7days' ? 'button-primary' : ''; ?>">
					<?php esc_html_e('7 days', 'baskerville'); ?>
				</a>
			</div>

			<?php if (!$has_data): ?>
				<div class="notice notice-info">
					<p><?php esc_html_e('No AI bot activity detected in the selected period.', 'baskerville'); ?></p>
				</div>
			<?php else: ?>

			<!-- Chart Container -->
			<div class="chart-container">
				<canvas id="aiBotsChart"></canvas>
			</div>

			<script>
			(function() {
				// Wait for Chart.js to load
				function initChart() {
					if (typeof Chart === 'undefined') {
						setTimeout(initChart, 100);
						return;
					}

					const data = <?php echo wp_json_encode($data); ?>;

					// Prepare labels (time slots)
					const labels = data.time_slots.map(slot => {
						const date = new Date(slot.replace(' ', 'T') + 'Z');
						const hours = String(date.getUTCHours()).padStart(2, '0');
						const minutes = String(date.getUTCMinutes()).padStart(2, '0');
						return hours + ':' + minutes;
					});

					// Company colors
					const companyColors = {
						'OpenAI': '#10a37f',
						'Anthropic': '#d4a574',
						'Google': '#4285f4',
						'Meta': '#0668e1',
						'ByteDance': '#fe2c55',
						'Amazon': '#ff9900',
						'Baidu': '#2932e1',
						'Perplexity': '#6366f1',
						'Cohere': '#7c3aed',
						'Common Crawl': '#9ca3af',
						'Huawei': '#e91e63',
						'Unknown': '#6b7280',
						'Generic': '#9ca3af',
					};

					// Prepare datasets
					const datasets = [];
					for (const [company, counts] of Object.entries(data.companies)) {
						datasets.push({
							label: company,
							data: counts,
							backgroundColor: companyColors[company] || '#9ca3af',
							borderColor: companyColors[company] || '#9ca3af',
							borderWidth: 1
						});
					}

					// Create chart
					const ctx = document.getElementById('aiBotsChart').getContext('2d');
					new Chart(ctx, {
						type: 'bar',
						data: {
							labels: labels,
							datasets: datasets
						},
						options: {
							responsive: true,
							maintainAspectRatio: true,
							interaction: {
								mode: 'index',
								intersect: false
							},
							scales: {
								x: {
									stacked: true,
									title: {
										display: true,
										text: '<?php echo esc_js( __( 'Time (UTC)', 'baskerville' ) ); ?>'
									},
									ticks: {
										maxRotation: 45,
										minRotation: 45
									}
								},
								y: {
									stacked: true,
									beginAtZero: true,
									title: {
										display: true,
										text: '<?php echo esc_js( __( 'Hits', 'baskerville' ) ); ?>'
									}
								}
							},
							plugins: {
								title: {
									display: true,
									text: '<?php echo esc_js( __( 'AI Bot Hits by Company - Last', 'baskerville' ) ); ?> ' + data.hours + 'h',
									font: {
										size: 16,
										weight: 'bold'
									}
								},
								legend: {
									display: true,
									position: 'bottom'
								},
								tooltip: {
									callbacks: {
										footer: function(items) {
											let total = 0;
											items.forEach(item => {
												total += item.parsed.y;
											});
											return 'Total: ' + total;
										}
									}
								}
							}
						}
					});
				}

				// Start initialization
				if (document.readyState === 'loading') {
					document.addEventListener('DOMContentLoaded', initChart);
				} else {
					initChart();
				}
			})();
			</script>

			<?php endif; ?>

		</div>

		<?php
	}

	public function ajax_install_maxmind() {
		check_ajax_referer('baskerville_install_maxmind', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville')));
		}

		$installer = new Baskerville_MaxMind_Installer();
		$result = $installer->install();

		if ($result['success']) {
			wp_send_json_success($result);
		} else {
			wp_send_json_error($result);
		}
	}

	public function ajax_clear_geoip_cache() {
		check_ajax_referer('baskerville_clear_geoip_cache', 'nonce');

		if (!current_user_can('manage_options')) {
			wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville')));
		}

		$core = new Baskerville_Core();
		$cleared = $core->fc_clear_geoip_cache();

		wp_send_json_success(array(
			/* translators: %d is the number of cache entries cleared */
			'message' => sprintf(__('Cleared %d GeoIP cache entries', 'baskerville'), $cleared),
			'cleared' => $cleared
		));
	}

	private function render_geoip_test_tab() {
		// Always use current IP
		$current_ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
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
					$block_reason = $would_block ? 'Country IS in blacklist' : 'Country NOT in blacklist';
				} elseif ($geoip_mode === 'whitelist' && !empty($whitelist_countries)) {
					$whitelist_arr = array_map('trim', array_map('strtoupper', explode(',', $whitelist_countries)));
					$would_block = !in_array($detected_country, $whitelist_arr, true);
					$block_reason = $would_block ? 'Country NOT in whitelist' : 'Country in whitelist';
				}
			}
			?>

			<!-- GeoIP Ban Status Card -->
			<div class="geoip-test-form baskerville-mb-20">
				<h2>🚫 <?php esc_html_e('GeoIP Country Ban Status', 'baskerville'); ?></h2>
				<table class="widefat baskerville-mt-15">
					<tr>
						<td class="baskerville-td-label baskerville-td-label-wide"><?php esc_html_e('Your IP Address', 'baskerville'); ?></td>
						<td><code><?php echo esc_html($current_ip); ?></code></td>
					</tr>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Detected Country', 'baskerville'); ?></td>
						<td>
							<?php if ($detected_country): ?>
								<strong class="baskerville-text-primary baskerville-text-lg"><?php echo esc_html($detected_country); ?></strong>
							<?php else: ?>
								<span class="baskerville-text-danger">❌ <?php esc_html_e('NOT DETECTED - GeoIP not configured', 'baskerville'); ?></span>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('GeoIP Mode', 'baskerville'); ?></td>
						<td>
							<strong><?php echo esc_html($geoip_mode); ?></strong>
							<?php if ($geoip_mode === 'allow_all'): ?>
								<span class="baskerville-text-success"> (<?php esc_html_e('All countries allowed', 'baskerville'); ?>)</span>
							<?php endif; ?>
						</td>
					</tr>
					<?php if ($geoip_mode === 'blacklist'): ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Block List Countries', 'baskerville'); ?></td>
						<td>
							<?php if (!empty($blacklist_countries)): ?>
								<code><?php echo esc_html($blacklist_countries); ?></code>
							<?php else: ?>
								<em class="baskerville-text-muted"><?php esc_html_e('(empty - no countries in block list)', 'baskerville'); ?></em>
							<?php endif; ?>
						</td>
					</tr>
					<?php endif; ?>
					<?php if ($geoip_mode === 'whitelist'): ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('Allow List Countries', 'baskerville'); ?></td>
						<td>
							<?php if (!empty($whitelist_countries)): ?>
								<code><?php echo esc_html($whitelist_countries); ?></code>
							<?php else: ?>
								<em class="baskerville-text-muted"><?php esc_html_e('(empty - all countries blocked)', 'baskerville'); ?></em>
							<?php endif; ?>
						</td>
					</tr>
					<?php endif; ?>
					<tr>
						<td class="baskerville-td-label"><?php esc_html_e('IP in Allow List?', 'baskerville'); ?></td>
						<td>
							<?php if ($is_whitelisted): ?>
								<span class="baskerville-status-yes"><?php esc_html_e( '✓ YES (bypasses all protection)', 'baskerville' ); ?></span>
							<?php else: ?>
								<span class="baskerville-text-muted"><?php esc_html_e( 'NO', 'baskerville' ); ?></span>
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
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville'); ?></span>
						<?php elseif (!$detected_country): ?>
							⚠️ <span class="baskerville-text-warning"><?php esc_html_e('ALLOWED (by default)', 'baskerville'); ?></span>
						<?php elseif ($geoip_mode === 'allow_all'): ?>
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville'); ?></span>
						<?php elseif ($would_block): ?>
							❌ <span class="baskerville-text-danger"><?php esc_html_e('BLOCKED', 'baskerville'); ?></span>
						<?php else: ?>
							✅ <span class="baskerville-status-yes"><?php esc_html_e('ALLOWED', 'baskerville'); ?></span>
						<?php endif; ?>
					</h3>
					<p class="baskerville-mt-0 baskerville-font-sm">
						<?php if ($is_whitelisted): ?>
							<?php esc_html_e('This IP is in the IP Allow List and bypasses all protection including GeoIP bans.', 'baskerville'); ?>
						<?php elseif (!$detected_country): ?>
							<?php esc_html_e('Country not detected. GeoIP database might be missing. Go to "GeoIP Configuration Status" below to check.', 'baskerville'); ?>
						<?php elseif ($geoip_mode === 'allow_all'): ?>
							<?php esc_html_e('GeoIP mode is set to "Allow All". Go to Countries tab to enable blocking.', 'baskerville'); ?>
						<?php elseif ($would_block): ?>
							<strong><?php esc_html_e('Reason:', 'baskerville'); ?></strong> <?php echo esc_html($block_reason); ?><br>
							<?php esc_html_e('This IP would receive 403 Forbidden on the website.', 'baskerville'); ?>
						<?php else: ?>
							<strong><?php esc_html_e('Reason:', 'baskerville'); ?></strong> <?php echo esc_html($block_reason); ?>
						<?php endif; ?>
					</p>
				</div>
			</div>

			<div class="geoip-test-form">
				<h2><?php esc_html_e('GeoIP Configuration Status', 'baskerville'); ?></h2>
				<p><?php esc_html_e('This page shows which GeoIP sources are configured and working for your server.', 'baskerville'); ?></p>
			</div>

			<?php if ($error): ?>
				<div class="baskerville-alert baskerville-alert-danger baskerville-alert-xl baskerville-mt-20">
					<h3 class="baskerville-text-danger baskerville-mt-0">❌ <?php esc_html_e('Error', 'baskerville'); ?></h3>
					<p><strong><?php esc_html_e('Critical error occurred:', 'baskerville'); ?></strong></p>
					<pre class="baskerville-pre baskerville-code-sm"><?php echo esc_html($error); ?></pre>
					<p class="baskerville-mb-0">
						<small><?php esc_html_e('Please report this error to plugin support.', 'baskerville'); ?></small>
					</p>
				</div>
			<?php elseif ($results): ?>
				<div class="geoip-info-box">
					<strong><?php esc_html_e('Your IP:', 'baskerville'); ?></strong> <code><?php echo esc_html($current_ip); ?></code>
					<br><strong><?php esc_html_e('Priority order:', 'baskerville'); ?></strong> NGINX GeoIP2 → NGINX GeoIP Legacy → NGINX Custom Header → Cloudflare → MaxMind
				</div>

				<div class="geoip-results">
					<h2><?php esc_html_e('GeoIP Test Results', 'baskerville'); ?></h2>

					<!-- NGINX GeoIP2 -->
					<div class="geoip-source <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_geoip2'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name">NGINX GeoIP2</div>
						<div class="geoip-source-result <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_geoip2'] ? esc_html($results['nginx_geoip2']) : esc_html__('Not configured', 'baskerville'); ?>
						</div>
					</div>

					<!-- NGINX GeoIP Legacy -->
					<div class="geoip-source <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_geoip_legacy'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name">NGINX GeoIP (legacy)</div>
						<div class="geoip-source-result <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_geoip_legacy'] ? esc_html($results['nginx_geoip_legacy']) : esc_html__('Not configured', 'baskerville'); ?>
						</div>
					</div>

					<!-- NGINX Custom Header -->
					<div class="geoip-source <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['nginx_custom_header'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name">NGINX Custom Header</div>
						<div class="geoip-source-result <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['nginx_custom_header'] ? esc_html($results['nginx_custom_header']) : esc_html__('Not configured', 'baskerville'); ?>
						</div>
					</div>

					<!-- Cloudflare -->
					<div class="geoip-source <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['cloudflare'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name">Cloudflare</div>
						<div class="geoip-source-result <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
							<?php echo $results['cloudflare'] ? esc_html($results['cloudflare']) : esc_html__('Not available', 'baskerville'); ?>
						</div>
					</div>

					<!-- MaxMind -->
					<div class="geoip-source <?php echo $results['maxmind'] ? 'available' : 'unavailable'; ?>">
						<div class="geoip-status-icon"><?php echo $results['maxmind'] ? '✅' : '❌'; ?></div>
						<div class="geoip-source-name">MaxMind GeoLite2</div>
						<div class="geoip-source-result <?php echo $results['maxmind'] ? 'available' : 'unavailable'; ?>">
							<?php
							if ($results['maxmind']) {
								echo esc_html($results['maxmind']);
							} else {
								echo esc_html__('Database not found or not configured', 'baskerville');
							}
							?>
						</div>
					</div>
				</div>

				<!-- MaxMind Debug Information -->
				<?php if (isset($results['maxmind_debug'])): ?>
				<div class="baskerville-debug-box">
					<h3><?php esc_html_e('MaxMind Debug Information', 'baskerville'); ?></h3>
					<table class="baskerville-debug-table-full">
						<tr>
							<td>Expected DB Path:</td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['expected_path']); ?></code>
							</td>
						</tr>
						<tr>
							<td>File Exists:</td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['file_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['file_exists'] ? 'YES ✓' : 'NO ✗'; ?>
								</span>
							</td>
						</tr>
						<tr>
							<td>File Readable:</td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['is_readable'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['is_readable'] ? 'YES ✓' : 'NO ✗'; ?>
								</span>
							</td>
						</tr>
						<tr>
							<td>File Size:</td>
							<td>
								<?php
								if ($results['maxmind_debug']['file_size'] > 0) {
									echo number_format($results['maxmind_debug']['file_size'] / 1024 / 1024, 2) . ' MB';
								} else {
									echo '<span class="baskerville-text-danger">0 bytes</span>';
								}
								?>
							</td>
						</tr>
						<tr>
							<td>WP_CONTENT_DIR:</td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['wp_content_dir']); ?></code>
							</td>
						</tr>
						<tr>
							<td>Autoload Path:</td>
							<td>
								<code><?php echo esc_html($results['maxmind_debug']['autoload_path']); ?></code>
							</td>
						</tr>
						<tr>
							<td>Autoload Exists:</td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['autoload_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['autoload_exists'] ? 'YES ✓' : 'NO ✗'; ?>
								</span>
							</td>
						</tr>
						<tr>
							<td>GeoIp2 Class Available:</td>
							<td>
								<span class="<?php echo $results['maxmind_debug']['class_exists'] ? 'baskerville-status-yes' : 'baskerville-status-no'; ?>">
									<?php echo $results['maxmind_debug']['class_exists'] ? 'YES ✓' : 'NO ✗'; ?>
								</span>
							</td>
						</tr>
						<?php if (isset($results['maxmind_debug']['error'])): ?>
						<tr class="baskerville-alert-danger">
							<td>Error Message:</td>
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
							<strong>⚠️ <?php esc_html_e('Database file not found!', 'baskerville'); ?></strong><br>
							<?php esc_html_e('Please upload GeoLite2-Country.mmdb to:', 'baskerville'); ?><br>
							<code class="baskerville-code-block">
								<?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
							</code>
							<strong><?php esc_html_e('Download from:', 'baskerville'); ?></strong>
							<a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank">MaxMind GeoLite2</a>
						</div>
					<?php elseif (!$results['maxmind_debug']['is_readable']): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('Database file exists but is not readable!', 'baskerville'); ?></strong><br>
							<?php esc_html_e('Check file permissions. Try:', 'baskerville'); ?><br>
							<code class="baskerville-code-block">
								chmod 644 <?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
							</code>
						</div>
					<?php elseif (!$results['maxmind_debug']['autoload_exists']): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('MaxMind PHP library not installed!', 'baskerville'); ?></strong><br>
							<?php esc_html_e('Click the button below to install automatically (no Composer required):', 'baskerville'); ?><br>

							<button id="baskerville-install-maxmind" class="button button-primary baskerville-mt-15">
								<?php esc_html_e('Install MaxMind Library', 'baskerville'); ?>
							</button>
							<span id="baskerville-install-status" class="baskerville-ml-10"></span>

							<div class="baskerville-mt-15 baskerville-divider-top">
								<small><strong><?php esc_html_e('Or install manually with Composer:', 'baskerville'); ?></strong></small><br>
								<code class="baskerville-code-block baskerville-code-sm">
									cd <?php echo esc_html(BASKERVILLE_PLUGIN_PATH); ?><br>
									composer require geoip2/geoip2
								</code>
							</div>
						</div>

						<script>
						jQuery(document).ready(function($) {
							$('#baskerville-install-maxmind').on('click', function(e) {
								e.preventDefault();
								var $btn = $(this);
								var $status = $('#baskerville-install-status');

								$btn.prop('disabled', true).text('<?php esc_html_e('Installing...', 'baskerville'); ?>');
								$status.html('<span class="baskerville-status-pending">⏳ <?php esc_html_e('Downloading and installing library...', 'baskerville'); ?></span>');

								$.ajax({
									url: ajaxurl,
									type: 'POST',
									data: {
										action: 'baskerville_install_maxmind',
										nonce: '<?php echo esc_js(wp_create_nonce('baskerville_install_maxmind')); ?>'
									},
									success: function(response) {
										if (response.success) {
											$status.html('<span class="baskerville-status-success">✓ ' + response.data.message + '</span>');
											setTimeout(function() {
												location.reload();
											}, 2000);
										} else {
											var errorMsg = response.data.message || 'Installation failed';
											var errorHtml = '<span class="baskerville-status-error">✗ ' + errorMsg + '</span>';

											// Show detailed errors if available
											if (response.data.errors && response.data.errors.length > 0) {
												errorHtml += '<br><small class="baskerville-status-error-detail">Details: ' + response.data.errors.join(', ') + '</small>';
											}

											$status.html(errorHtml);
											$btn.prop('disabled', false).text('<?php esc_html_e('Retry Installation', 'baskerville'); ?>');
										}
									},
									error: function() {
										$status.html('<span class="baskerville-status-error">✗ <?php esc_html_e('Installation failed. Please try again.', 'baskerville'); ?></span>');
										$btn.prop('disabled', false).text('<?php esc_html_e('Install MaxMind Library', 'baskerville'); ?>');
									}
								});
							});
						});
						</script>
					<?php elseif ($results['maxmind_debug']['file_size'] == 0): ?>
						<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg baskerville-alert-mt">
							<strong>⚠️ <?php esc_html_e('Database file is empty (0 bytes)!', 'baskerville'); ?></strong><br>
							<?php esc_html_e('The file exists but has no data. Please re-download and upload the database.', 'baskerville'); ?>
						</div>
					<?php endif; ?>
				</div>
				<?php endif; ?>

				<?php
				// Show which source would be used
				$active_source = null;
				$active_country = null;
				if ($results['nginx_geoip2']) {
					$active_source = 'NGINX GeoIP2';
					$active_country = $results['nginx_geoip2'];
				} elseif ($results['nginx_geoip_legacy']) {
					$active_source = 'NGINX GeoIP (legacy)';
					$active_country = $results['nginx_geoip_legacy'];
				} elseif ($results['nginx_custom_header']) {
					$active_source = 'NGINX Custom Header';
					$active_country = $results['nginx_custom_header'];
				} elseif ($results['cloudflare']) {
					$active_source = 'Cloudflare';
					$active_country = $results['cloudflare'];
				} elseif ($results['maxmind']) {
					$active_source = 'MaxMind GeoLite2';
					$active_country = $results['maxmind'];
				}
				?>

				<div class="geoip-info-box baskerville-alert-success baskerville-mt-20">
					<strong><?php esc_html_e('Active Source:', 'baskerville'); ?></strong>
					<?php echo $active_source ? esc_html($active_source) : esc_html__('None available', 'baskerville'); ?>
					<?php if ($active_country): ?>
						<br><strong><?php esc_html_e('Country Code:', 'baskerville'); ?></strong>
						<span class="baskerville-status-yes baskerville-text-lg"><?php echo esc_html($active_country); ?></span>
					<?php endif; ?>
				</div>

				<!-- Clear GeoIP Cache Button -->
				<div class="baskerville-debug-box">
					<h3><?php esc_html_e('GeoIP Cache Management', 'baskerville'); ?></h3>
					<p><?php esc_html_e('If you are using a VPN or your IP location has changed, you may need to clear the GeoIP cache to see the updated country detection.', 'baskerville'); ?></p>
					<p><?php esc_html_e('Cache TTL: 7 days', 'baskerville'); ?></p>

					<button id="baskerville-clear-geoip-cache" class="button button-secondary baskerville-mt-10">
						🗑️ <?php esc_html_e('Clear GeoIP Cache', 'baskerville'); ?>
					</button>
					<span id="baskerville-clear-cache-status" class="baskerville-ml-10"></span>
				</div>

				<script>
				jQuery(document).ready(function($) {
					$('#baskerville-clear-geoip-cache').on('click', function(e) {
						e.preventDefault();
						var $btn = $(this);
						var $status = $('#baskerville-clear-cache-status');

						$btn.prop('disabled', true).text('<?php esc_html_e('Clearing...', 'baskerville'); ?>');
						$status.html('<span class="baskerville-status-pending">⏳ <?php esc_html_e('Clearing cache...', 'baskerville'); ?></span>');

						$.ajax({
							url: ajaxurl,
							type: 'POST',
							data: {
								action: 'baskerville_clear_geoip_cache',
								nonce: '<?php echo esc_js(wp_create_nonce('baskerville_clear_geoip_cache')); ?>'
							},
							success: function(response) {
								if (response.success) {
									$status.html('<span class="baskerville-status-success">✓ ' + response.data.message + '</span>');
									$btn.text('🗑️ <?php esc_html_e('Clear GeoIP Cache', 'baskerville'); ?>');
									setTimeout(function() {
										location.reload();
									}, 1500);
								} else {
									var errorMsg = response.data.message || 'Failed to clear cache';
									$status.html('<span class="baskerville-status-error">✗ ' + errorMsg + '</span>');
									$btn.prop('disabled', false).text('🗑️ <?php esc_html_e('Clear GeoIP Cache', 'baskerville'); ?>');
								}
							},
							error: function() {
								$status.html('<span class="baskerville-status-error">✗ <?php esc_html_e('Failed to clear cache. Please try again.', 'baskerville'); ?></span>');
								$btn.prop('disabled', false).text('🗑️ <?php esc_html_e('Clear GeoIP Cache', 'baskerville'); ?>');
							}
						});
					});
				});
				</script>
			<?php endif; ?>
		</div>
		<?php
	}

	public function admin_page() {
		// Check user capabilities
		if (!current_user_can('manage_options')) {
			wp_die(esc_html__('You do not have sufficient permissions to access this page.', 'baskerville'));
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
								<?php esc_html_e('MASTER SWITCH', 'baskerville'); ?>
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
									<?php echo $master_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
				<a href="?page=baskerville-settings&tab=live-feed"
				   class="nav-tab <?php echo $current_tab === 'live-feed' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Live Feed', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=bot-protection"
				   class="nav-tab <?php echo $bot_protection_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'bot-protection' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Bot Control', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=ai-bot-control"
				   class="nav-tab <?php echo $ai_bot_control_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'ai-bot-control' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('AI Bot Control', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=country-control"
				   class="nav-tab <?php echo $geoip_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'country-control' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Country Control', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=burst-protection"
				   class="nav-tab <?php echo $burst_protection_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'burst-protection' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Burst Protection', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=rate-limits"
				   class="nav-tab <?php echo $api_rate_limit_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'rate-limits' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Rate Limits', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=turnstile"
				   class="nav-tab <?php echo $turnstile_enabled ? 'tab-enabled' : ''; ?> <?php echo $current_tab === 'turnstile' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Turnstile', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=analytics"
				   class="nav-tab <?php echo $current_tab === 'analytics' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Analytics', 'baskerville'); ?>
				</a>
				<a href="?page=baskerville-settings&tab=settings"
				   class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
					<?php esc_html_e('Settings', 'baskerville'); ?>
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
											<?php esc_html_e('Bot Control', 'baskerville'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[bot_protection_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[bot_protection_enabled]" value="1" <?php checked($bot_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $bot_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
								<th scope="row"><?php esc_html_e('Verified Crawlers', 'baskerville'); ?></th>
								<td>
									<label>
										<input type="hidden" name="baskerville_settings[allow_verified_crawlers]" value="0">
										<input type="checkbox" name="baskerville_settings[allow_verified_crawlers]" value="1" <?php checked($allow_verified, true); ?> />
										<?php esc_html_e('Allow verified crawlers (Google, Bing, Yandex, etc.)', 'baskerville'); ?>
									</label>
									<p class="description">
										<?php esc_html_e('Verified crawlers are identified by reverse DNS lookup. When enabled, they bypass bot protection.', 'baskerville'); ?>
									</p>
								</td>
							</tr>
							<?php
							$ban_all_bots = isset($options['ban_all_detected_bots']) ? $options['ban_all_detected_bots'] : false;
							$instant_ban_threshold = isset($options['instant_ban_threshold']) ? (int) $options['instant_ban_threshold'] : 85;
							?>
							<tr>
								<th scope="row"><?php esc_html_e('Ban All Detected Bots', 'baskerville'); ?></th>
								<td>
									<label>
										<input type="hidden" name="baskerville_settings[ban_all_detected_bots]" value="0">
										<input type="checkbox" name="baskerville_settings[ban_all_detected_bots]" value="1" <?php checked($ban_all_bots, true); ?> />
										<?php esc_html_e('Ban all bots detected (not just "bad bots")', 'baskerville'); ?>
									</label>
									<p class="description">
										<?php esc_html_e('When enabled, all visitors classified as "bot" (score ≥70) will be banned after exceeding burst threshold. This includes crawlers like SemrushBot, AhrefsBot, MJ12bot, etc.', 'baskerville'); ?>
									</p>
								</td>
							</tr>
							<tr>
								<th scope="row"><?php esc_html_e('Instant Ban Threshold', 'baskerville'); ?></th>
								<td>
									<input type="number" name="baskerville_settings[instant_ban_threshold]" value="<?php echo esc_attr($instant_ban_threshold); ?>" min="0" max="100" step="5" class="baskerville-input-sm" />
									<p class="description">
										<?php esc_html_e('Bot score threshold for immediate ban (without waiting for burst). Default: 85.', 'baskerville'); ?><br>
										<?php esc_html_e('Visitors with score ≥ this value AND non-browser User-Agent will be banned instantly on first request.', 'baskerville'); ?><br><br>
										<strong><?php esc_html_e('Score examples:', 'baskerville'); ?></strong><br>
										• <?php esc_html_e('0-30: Normal browser with good headers', 'baskerville'); ?><br>
										• <?php esc_html_e('30-60: Suspicious (old browser, missing headers)', 'baskerville'); ?><br>
										• <?php esc_html_e('60-80: Likely bot (bot UA, HTTP/1.x, automation signs)', 'baskerville'); ?><br>
										• <?php esc_html_e('80-100: Definitely bot (webdriver, known bot UA)', 'baskerville'); ?>
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
											<?php esc_html_e('AI Bot Control', 'baskerville'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[ai_bot_control_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[ai_bot_control_enabled]" value="1" <?php checked($ai_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $ai_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
								<strong><?php esc_html_e('GeoIP Source:', 'baskerville'); ?></strong> <?php echo esc_html($geoip_status['source']); ?>
								<?php if (!empty($geoip_status['country'])): ?>
									&mdash; <?php esc_html_e('Your country:', 'baskerville'); ?> <strong><?php echo esc_html($geoip_status['country']); ?></strong>
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
								<strong class="baskerville-text-warning"><?php esc_html_e('No GeoIP source configured!', 'baskerville'); ?></strong><br>
								<span class="baskerville-text-warning">
									<?php
									printf(
										/* translators: %s: link to settings tab */
										esc_html__('Country blocking will not work. Go to %s to install MaxMind GeoLite2 database.', 'baskerville'),
										'<a href="' . esc_url(admin_url('options-general.php?page=baskerville-settings&tab=settings')) . '"><strong>' . esc_html__('Settings tab', 'baskerville') . '</strong></a>'
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
											<?php esc_html_e('Country Control', 'baskerville'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[geoip_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[geoip_enabled]" value="1" <?php checked($geoip_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $geoip_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
											<?php esc_html_e('Burst Protection', 'baskerville'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[burst_protection_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[burst_protection_enabled]" value="1" <?php checked($burst_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $burst_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
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
											<?php esc_html_e('Rate Limits', 'baskerville'); ?>
										</span>
										<input type="hidden" name="baskerville_settings[api_rate_limit_enabled]" value="0">
										<label class="baskerville-toggle-switch">
											<input type="checkbox" name="baskerville_settings[api_rate_limit_enabled]" value="1" <?php checked($rate_limit_enabled, true); ?> />
											<span class="baskerville-toggle-slider-regular"></span>
										</label>
										<span class="baskerville-toggle-text">
											<?php echo $rate_limit_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
										</span>
									</div>
								</td>
							</tr>
						</table>
						<?php
						submit_button();
						?>

						<div class="baskerville-info-box">
							<h3><?php esc_html_e('How Rate Limiting Works', 'baskerville'); ?></h3>
							<p>
								<?php esc_html_e('Rate limiting protects your API endpoints from abuse by limiting the number of requests per IP address within a time window.', 'baskerville'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('Protected endpoints:', 'baskerville'); ?></strong>
								<?php esc_html_e('REST API (/wp-json/), GraphQL, XML-RPC, and webhook URLs.', 'baskerville'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('When limit is exceeded:', 'baskerville'); ?></strong>
								<?php esc_html_e('Returns HTTP 429 (Too Many Requests) with Retry-After header.', 'baskerville'); ?>
							</p>
							<p>
								<strong><?php esc_html_e('Example:', 'baskerville'); ?></strong>
								<?php
								printf(
									/* translators: 1: number of requests, 2: time window in seconds */
									esc_html__('With default settings (100 requests / 60 seconds), an IP making more than 100 API calls per minute will be temporarily blocked.', 'baskerville')
								);
								?>
							</p>
						</div>
						<table class="form-table" role="presentation">
							<tr>
								<th scope="row">
									<label for="api_rate_limit_requests">
										<?php esc_html_e('Request Limit', 'baskerville'); ?>
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
									<?php esc_html_e('requests', 'baskerville'); ?>
									<p class="description">
										<?php esc_html_e('Maximum number of requests allowed per IP address.', 'baskerville'); ?>
									</p>
								</td>
							</tr>
							<tr>
								<th scope="row">
									<label for="api_rate_limit_window">
										<?php esc_html_e('Time Window', 'baskerville'); ?>
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
									<?php esc_html_e('seconds', 'baskerville'); ?>
									<p class="description">
										<?php esc_html_e('Time window for the rate limit (60 seconds = 1 minute).', 'baskerville'); ?>
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
				🛡️ <?php esc_html_e('Bot Control', 'baskerville'); ?>
				<span class="baskerville-section-status <?php echo $enabled ? 'enabled' : 'disabled'; ?>">
					<?php echo $enabled ? '✓ ENABLED' : 'DISABLED'; ?>
				</span>
			</h2>
			<p><?php esc_html_e('Automatic protection from malicious bots, scrapers, and suspicious user agents', 'baskerville'); ?></p>
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
				🚦 <?php esc_html_e('Rate Limits', 'baskerville'); ?>
				<span class="baskerville-rate-status <?php echo $enabled ? 'baskerville-rate-status-on' : 'baskerville-rate-status-off'; ?>">
					<?php echo $enabled ? '✓ ENABLED' : 'DISABLED'; ?>
				</span>
			</h2>
			<p class="baskerville-rate-desc">
				<?php esc_html_e('API and endpoint rate limiting', 'baskerville'); ?>
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
							<?php echo $enabled ? esc_html__('Rate Limits ON', 'baskerville') : esc_html__('Rate Limits OFF', 'baskerville'); ?>
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
								<?php esc_html_e('Cloudflare Turnstile', 'baskerville'); ?>
							</span>
							<input type="hidden" name="baskerville_settings[turnstile_enabled]" value="0">
							<label class="baskerville-toggle-switch">
								<input type="checkbox" name="baskerville_settings[turnstile_enabled]" value="1" <?php checked($turnstile_enabled, true); ?> />
								<span class="baskerville-toggle-slider-regular"></span>
							</label>
							<span class="baskerville-toggle-text">
								<?php echo $turnstile_enabled ? esc_html__('ON', 'baskerville') : esc_html__('OFF', 'baskerville'); ?>
							</span>
						</div>
						<p class="description baskerville-mt-10">
							<?php esc_html_e('When enabled, Turnstile challenge will be shown on sensitive pages:', 'baskerville'); ?>
							<strong>wp-login.php</strong>,
							<strong><?php esc_html_e('Registration', 'baskerville'); ?></strong>,
							<strong><?php esc_html_e('Comment form', 'baskerville'); ?></strong>
						</p>
					</td>
				</tr>
			</table>
			<?php submit_button(); ?>

			<!-- Bot Score Challenge Settings -->
			<div class="baskerville-form-container">
				<h3 class="baskerville-section-title"><?php esc_html_e('Bot Score Challenge', 'baskerville'); ?></h3>
				<p class="description">
					<?php esc_html_e('Show Turnstile challenge to visitors with borderline bot scores instead of blocking them outright.', 'baskerville'); ?>
				</p>

				<?php
				$challenge_borderline = isset($options['turnstile_challenge_borderline']) ? (bool) $options['turnstile_challenge_borderline'] : false;
				$borderline_min = isset($options['turnstile_borderline_min']) ? (int) $options['turnstile_borderline_min'] : 40;
				$borderline_max = isset($options['turnstile_borderline_max']) ? (int) $options['turnstile_borderline_max'] : 70;
				$is_disabled = !$turnstile_enabled || empty($site_key) || empty($secret_key);
				?>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row"><?php esc_html_e('Enable', 'baskerville'); ?></th>
						<td>
							<label>
								<input type="hidden" name="baskerville_settings[turnstile_challenge_borderline]" value="0">
								<input type="checkbox"
									   name="baskerville_settings[turnstile_challenge_borderline]"
									   value="1"
									   <?php checked($challenge_borderline, true); ?>
									   <?php disabled($is_disabled, true); ?>
								/>
								<?php esc_html_e('Use Turnstile challenge for borderline bot scores', 'baskerville'); ?>
							</label>
							<?php if ($is_disabled): ?>
								<p class="description baskerville-text-danger">
									<?php esc_html_e('Enable Turnstile and configure keys above to use this feature.', 'baskerville'); ?>
								</p>
							<?php else: ?>
								<p class="description">
									<?php esc_html_e('Instead of blocking visitors with uncertain bot scores, show them a Turnstile challenge. If they pass, they are allowed through.', 'baskerville'); ?>
								</p>
							<?php endif; ?>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label><?php esc_html_e('Score Range', 'baskerville'); ?></label>
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
							<span class="baskerville-mx-10"><?php esc_html_e('to', 'baskerville'); ?></span>
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
								<?php esc_html_e('Bot score range (0-100) that triggers Turnstile challenge.', 'baskerville'); ?><br>
								<strong><?php esc_html_e('Recommended:', 'baskerville'); ?></strong> 40-70<br>
								<span class="baskerville-text-muted">
									• 0-39: <?php esc_html_e('Likely human (allowed)', 'baskerville'); ?><br>
									• 40-70: <?php esc_html_e('Borderline (show Turnstile)', 'baskerville'); ?><br>
									• 71-100: <?php esc_html_e('Likely bot (blocked)', 'baskerville'); ?>
								</span>
							</p>
						</td>
					</tr>
					<?php
					$under_attack_mode = isset($options['turnstile_under_attack']) ? (bool) $options['turnstile_under_attack'] : false;
					?>
					<tr>
						<th scope="row"><?php esc_html_e('Under Attack Mode', 'baskerville'); ?></th>
						<td>
							<label class="<?php echo $under_attack_mode ? 'baskerville-text-danger-bold' : ''; ?>">
								<input type="hidden" name="baskerville_settings[turnstile_under_attack]" value="0">
								<input type="checkbox"
									   name="baskerville_settings[turnstile_under_attack]"
									   value="1"
									   <?php checked($under_attack_mode, true); ?>
									   <?php disabled($is_disabled, true); ?>
								/>
								<?php esc_html_e('Show Turnstile challenge to ALL visitors', 'baskerville'); ?>
							</label>
							<?php if ($under_attack_mode): ?>
								<p class="description baskerville-text-danger-bold">
									<span class="dashicons dashicons-warning baskerville-text-danger"></span>
									<?php esc_html_e('ACTIVE: All visitors must pass Turnstile challenge!', 'baskerville'); ?>
								</p>
							<?php else: ?>
								<p class="description">
									<?php esc_html_e('Emergency mode for when your site is under attack. When enabled, EVERY visitor (including those classified as human) must pass a Turnstile challenge before accessing the site.', 'baskerville'); ?><br><br>
									<strong><?php esc_html_e('Use this when:', 'baskerville'); ?></strong><br>
									• <?php esc_html_e('Your site is experiencing a DDoS or bot attack', 'baskerville'); ?><br>
									• <?php esc_html_e('You see unusual traffic patterns', 'baskerville'); ?><br>
									• <?php esc_html_e('Bots are bypassing normal detection', 'baskerville'); ?><br><br>
									<span class="baskerville-text-danger"><?php esc_html_e('Warning: This will add friction for real users. Disable when attack subsides.', 'baskerville'); ?></span>
								</p>
							<?php endif; ?>
						</td>
					</tr>
				</table>
			</div>

			<!-- Cloudflare Turnstile Configuration (API Keys) -->
			<div class="baskerville-form-container">
				<h3 class="baskerville-section-title"><?php esc_html_e('Cloudflare Turnstile Configuration', 'baskerville'); ?></h3>
				<p class="description">
					<?php
					printf(
						/* translators: %s: link to Cloudflare dashboard */
						esc_html__('Get your Site Key and Secret Key from the %s.', 'baskerville'),
						'<a href="https://dash.cloudflare.com/?to=/:account/turnstile" target="_blank">Cloudflare Dashboard</a>'
					);
					?>
				</p>

				<table class="form-table" role="presentation">
					<tr>
						<th scope="row">
							<label for="turnstile_site_key"><?php esc_html_e('Site Key', 'baskerville'); ?></label>
						</th>
						<td>
							<input type="text"
								   id="turnstile_site_key"
								   name="baskerville_settings[turnstile_site_key]"
								   value="<?php echo esc_attr($site_key); ?>"
								   class="regular-text"
								   placeholder="0x4AAAAAAA..."
							/>
							<p class="description"><?php esc_html_e('The public site key for your Turnstile widget.', 'baskerville'); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row">
							<label for="turnstile_secret_key"><?php esc_html_e('Secret Key', 'baskerville'); ?></label>
						</th>
						<td>
							<input type="password"
								   id="turnstile_secret_key"
								   name="baskerville_settings[turnstile_secret_key]"
								   value="<?php echo esc_attr($secret_key); ?>"
								   class="regular-text"
								   placeholder="0x4AAAAAAA..."
							/>
							<p class="description"><?php esc_html_e('The secret key for server-side verification. Keep this private!', 'baskerville'); ?></p>
						</td>
					</tr>
				</table>
			</div>

			<?php submit_button(); ?>
		</form>

		<!-- Turnstile Widget Test -->
		<div class="baskerville-form-container">
			<h3 class="baskerville-section-title"><?php esc_html_e('Widget Test', 'baskerville'); ?></h3>

			<?php if (empty($site_key)): ?>
				<div class="baskerville-warning-box">
					<strong><?php esc_html_e('Site Key not configured', 'baskerville'); ?></strong><br>
					<?php esc_html_e('Enter your Turnstile Site Key above and save to test the widget.', 'baskerville'); ?>
				</div>
			<?php else: ?>
				<p><?php esc_html_e('The Turnstile widget should appear below if configured correctly:', 'baskerville'); ?></p>

				<div id="turnstile-test-container" class="baskerville-test-container">
					<div class="cf-turnstile"
						 data-sitekey="<?php echo esc_attr($site_key); ?>"
						 data-callback="onTurnstileSuccess"
						 data-error-callback="onTurnstileError"
						 data-theme="light">
					</div>
				</div>

				<div id="turnstile-status" class="baskerville-test-status"></div>

				<?php // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent, WordPress.WP.EnqueuedResources.NonEnqueuedScript -- Cloudflare Turnstile API must be loaded from Cloudflare servers ?>
				<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
				<script>
				function onTurnstileSuccess(token) {
					var statusDiv = document.getElementById('turnstile-status');
					statusDiv.className = 'baskerville-test-status success';
					statusDiv.innerHTML = '<strong class="baskerville-test-success-text">✓ <?php echo esc_js(__('Turnstile widget is working!', 'baskerville')); ?></strong><br><small><?php echo esc_js(__('Token received (first 20 chars):', 'baskerville')); ?> ' + token.substring(0, 20) + '...</small>';
				}

				function onTurnstileError(error) {
					var statusDiv = document.getElementById('turnstile-status');
					statusDiv.className = 'baskerville-test-status error';
					statusDiv.innerHTML = '<strong class="baskerville-test-error-text">✗ <?php echo esc_js(__('Turnstile error:', 'baskerville')); ?></strong> ' + error;
				}
				</script>
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
		$base_url = admin_url('options-general.php?page=baskerville-settings&tab=analytics');
		?>

		<h2 class="baskerville-section-heading">
			<span class="dashicons dashicons-chart-area" ></span>
			<?php esc_html_e('Traffic Analytics', 'baskerville'); ?>
		</h2>

		<!-- Period Selection Buttons -->
		<div class="period-buttons">
			<a href="<?php echo esc_url($base_url . '&period=12h'); ?>"
			   class="button <?php echo $period === '12h' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('12h', 'baskerville'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=1day'); ?>"
			   class="button <?php echo $period === '1day' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('1 day', 'baskerville'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=3days'); ?>"
			   class="button <?php echo $period === '3days' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('3 days', 'baskerville'); ?>
			</a>
			<a href="<?php echo esc_url($base_url . '&period=7days'); ?>"
			   class="button <?php echo $period === '7days' ? 'button-primary' : ''; ?>">
				<?php esc_html_e('7 days', 'baskerville'); ?>
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
						<span class="baskerville-metric-label"><?php esc_html_e('Block Rate', 'baskerville'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-red"><?php echo esc_html($key_metrics['block_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-red" style="width: <?php echo esc_attr(min(100, $key_metrics['block_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: blocked IPs count, %2$s: total IPs count */
							esc_html__('%1$s blocked / %2$s total IPs', 'baskerville'),
							'<strong>' . number_format($key_metrics['blocked_ips']) . '</strong>',
							number_format($key_metrics['total_ips'])
						); ?>
					</div>
				</div>

				<!-- Challenge Rate -->
				<div class="baskerville-metric-card">
					<div class="baskerville-metric-header">
						<span class="baskerville-metric-label"><?php esc_html_e('Challenge Rate', 'baskerville'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-amber"><?php echo esc_html($key_metrics['challenge_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-amber" style="width: <?php echo esc_attr(min(100, $key_metrics['challenge_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: challenged IPs count, %2$s: total IPs count */
							esc_html__('%1$s challenged / %2$s total IPs', 'baskerville'),
							'<strong>' . number_format($key_metrics['challenged_ips']) . '</strong>',
							number_format($key_metrics['total_ips'])
						); ?>
					</div>
				</div>

				<!-- Passed Challenge Rate -->
				<div class="baskerville-metric-card">
					<div class="baskerville-metric-header">
						<span class="baskerville-metric-label"><?php esc_html_e('Passed Challenge', 'baskerville'); ?></span>
						<span class="baskerville-metric-value baskerville-metric-value-green"><?php echo esc_html($key_metrics['pass_rate']); ?>%</span>
					</div>
					<div class="baskerville-progress-bar">
						<div class="baskerville-progress-fill baskerville-progress-fill-green" style="width: <?php echo esc_attr(min(100, $key_metrics['pass_rate'])); ?>%;"></div>
					</div>
					<div class="baskerville-metric-subtext">
						<?php printf(
							/* translators: %1$s: passed IPs count, %2$s: challenged IPs count */
							esc_html__('%1$s passed / %2$s challenged IPs', 'baskerville'),
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
					<h3 class="baskerville-precision-title"><?php esc_html_e('Total Precision', 'baskerville'); ?></h3>
					<div id="turnstilePrecisionValue" class="baskerville-precision-value"></div>
					<p class="baskerville-precision-subtitle"><?php esc_html_e('% of challenges failed (bots caught)', 'baskerville'); ?></p>
					<div class="baskerville-precision-stats">
						<div id="turnstileStats"></div>
					</div>
				</div>
			</div>

			<?php if (is_array($timeseries)): ?>
			<script>
	// Wait for Chart.js to load
	(function waitForChart() {
		if (typeof Chart === 'undefined') {
			setTimeout(waitForChart, 100);
			return;
		}

		const timeseries = <?php echo wp_json_encode($timeseries); ?>;
		const hours = <?php echo absint($hours); ?>;

		// Check if we have data
		if (!timeseries || timeseries.length === 0) {
			document.getElementById('baskervilleHumAutoBar').parentElement.innerHTML = '<p class="baskerville-no-data"><?php echo esc_html__('No data available for the selected period', 'baskerville'); ?></p>';
			document.getElementById('baskervilleHumAutoPie').parentElement.innerHTML = '<p class="baskerville-no-data"><?php echo esc_html__('No data available', 'baskerville'); ?></p>';
			return;
		}

		// Format time for labels
		function fmtHHMM(timeStr) {
			const d = new Date(timeStr + 'Z');
			const hh = String(d.getHours()).padStart(2, '0');
			const mm = String(d.getMinutes()).padStart(2, '0');
			return hh + ':' + mm;
		}

		// Prepare data
		const labels = timeseries.map(i => fmtHHMM(i.time));
		const humans = timeseries.map(i => i.human_count || 0);
		const automated = timeseries.map(i =>
			(i.bad_bot_count||0) + (i.ai_bot_count||0) + (i.bot_count||0) + (i.verified_bot_count||0)
		);

		// Totals for pie chart
		const totalHumans = humans.reduce((a,b) => a+b, 0);
		const totalAutomated = automated.reduce((a,b) => a+b, 0);

		// 1) Stacked Bar: Humans vs Automated
		const barCtx = document.getElementById('baskervilleHumAutoBar').getContext('2d');
		new Chart(barCtx, {
			type: 'bar',
			data: {
				labels,
				datasets: [
					{
						label: '<?php echo esc_js( __( 'Humans', 'baskerville' ) ); ?>',
						data: humans,
						stack: 'visits',
						backgroundColor: '#4CAF50'
					},
					{
						label: '<?php echo esc_js( __( 'Automated', 'baskerville' ) ); ?>',
						data: automated,
						stack: 'visits',
						backgroundColor: '#FF9800'
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: true,
				interaction: { mode: 'index', intersect: false },
				scales: {
					x: { stacked: true, title: { display: true, text: '<?php echo esc_js( __( 'Time', 'baskerville' ) ); ?>' } },
					y: { stacked: true, beginAtZero: true, title: { display: true, text: '<?php echo esc_js( __( 'Visits', 'baskerville' ) ); ?>' } }
				},
				plugins: {
					title: { display: true, text: '<?php echo esc_js( __( 'Humans vs Automated — last', 'baskerville' ) ); ?> ' + hours + 'h' },
					tooltip: {
						callbacks: {
							afterBody(items) {
								const idx = items[0].dataIndex;
								const total = (humans[idx]||0) + (automated[idx]||0);
								const hp = total ? Math.round((humans[idx]*100)/total) : 0;
								const ap = total ? Math.round((automated[idx]*100)/total) : 0;
								return [`<?php echo esc_js( __( 'Total:', 'baskerville' ) ); ?> ${total}`, `<?php echo esc_js( __( 'Humans:', 'baskerville' ) ); ?> ${humans[idx]} (${hp}%)`, `<?php echo esc_js( __( 'Automated:', 'baskerville' ) ); ?> ${automated[idx]} (${ap}%)`];
							}
						}
					}
				}
			}
		});

		// 2) Pie: Totals Humans vs Automated
		const pieCtx = document.getElementById('baskervilleHumAutoPie').getContext('2d');
		new Chart(pieCtx, {
			type: 'pie',
			data: {
				labels: ['<?php echo esc_js( __( 'Humans', 'baskerville' ) ); ?>', '<?php echo esc_js( __( 'Automated', 'baskerville' ) ); ?>'],
				datasets: [{
					data: [totalHumans, totalAutomated],
					backgroundColor: ['#4CAF50', '#FF9800']
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: true,
				plugins: {
					title: { display: true, text: '<?php echo esc_js( __( 'Traffic Distribution — last', 'baskerville' ) ); ?> ' + hours + 'h' },
					legend: { position: 'bottom' },
					tooltip: {
						callbacks: {
							label(ctx) {
								const v = ctx.parsed || 0;
								const sum = totalHumans + totalAutomated || 1;
								const pct = Math.round((v*100)/sum);
								return ` ${ctx.label}: ${v} (${pct}%)`;
							}
						}
					}
				}
			}
		});

		// Prepare bot types data
		const badBots = timeseries.map(i => i.bad_bot_count || 0);
		const aiBots = timeseries.map(i => i.ai_bot_count || 0);
		const bots = timeseries.map(i => i.bot_count || 0);
		const verifiedBots = timeseries.map(i => i.verified_bot_count || 0);

		// Totals for bot types pie chart
		const totalBadBots = badBots.reduce((a,b) => a+b, 0);
		const totalAiBots = aiBots.reduce((a,b) => a+b, 0);
		const totalBots = bots.reduce((a,b) => a+b, 0);
		const totalVerifiedBots = verifiedBots.reduce((a,b) => a+b, 0);

		// 3) Stacked Bar: Bot Types over time
		const botTypesBarCtx = document.getElementById('baskervilleBotTypesBar').getContext('2d');
		new Chart(botTypesBarCtx, {
			type: 'bar',
			data: {
				labels,
				datasets: [
					{
						label: '<?php echo esc_js( __( 'Bad Bots', 'baskerville' ) ); ?>',
						data: badBots,
						stack: 'bots',
						backgroundColor: '#F44336'
					},
					{
						label: '<?php echo esc_js( __( 'AI Bots', 'baskerville' ) ); ?>',
						data: aiBots,
						stack: 'bots',
						backgroundColor: '#9C27B0'
					},
					{
						label: '<?php echo esc_js( __( 'Other Bots', 'baskerville' ) ); ?>',
						data: bots,
						stack: 'bots',
						backgroundColor: '#FF9800'
					},
					{
						label: '<?php echo esc_js( __( 'Verified Crawlers', 'baskerville' ) ); ?>',
						data: verifiedBots,
						stack: 'bots',
						backgroundColor: '#2196F3'
					}
				]
			},
			options: {
				responsive: true,
				maintainAspectRatio: true,
				interaction: { mode: 'index', intersect: false },
				scales: {
					x: { stacked: true, title: { display: true, text: '<?php echo esc_js( __( 'Time', 'baskerville' ) ); ?>' } },
					y: { stacked: true, beginAtZero: true, title: { display: true, text: '<?php echo esc_js( __( 'Count', 'baskerville' ) ); ?>' } }
				},
				plugins: {
					title: { display: true, text: '<?php echo esc_js( __( 'Bot Types — last', 'baskerville' ) ); ?> ' + hours + 'h' },
					tooltip: {
						callbacks: {
							afterBody(items) {
								const idx = items[0].dataIndex;
								const total = (badBots[idx]||0) + (aiBots[idx]||0) + (bots[idx]||0) + (verifiedBots[idx]||0);
								return [`<?php echo esc_js( __( 'Total bots:', 'baskerville' ) ); ?> ${total}`];
							}
						}
					}
				}
			}
		});

		// 4) Pie: Bot Types Distribution
		const botTypesPieCtx = document.getElementById('baskervilleBotTypesPie').getContext('2d');
		new Chart(botTypesPieCtx, {
			type: 'pie',
			data: {
				labels: ['<?php echo esc_js( __( 'Bad Bots', 'baskerville' ) ); ?>', '<?php echo esc_js( __( 'AI Bots', 'baskerville' ) ); ?>', '<?php echo esc_js( __( 'Other Bots', 'baskerville' ) ); ?>', '<?php echo esc_js( __( 'Verified Crawlers', 'baskerville' ) ); ?>'],
				datasets: [{
					data: [totalBadBots, totalAiBots, totalBots, totalVerifiedBots],
					backgroundColor: ['#F44336', '#9C27B0', '#FF9800', '#2196F3']
				}]
			},
			options: {
				responsive: true,
				maintainAspectRatio: true,
				plugins: {
					title: { display: true, text: '<?php echo esc_js( __( 'Bot Types Distribution — last', 'baskerville' ) ); ?> ' + hours + 'h' },
					legend: { position: 'bottom' },
					tooltip: {
						callbacks: {
							label(ctx) {
								const v = ctx.parsed || 0;
								const sum = totalBadBots + totalAiBots + totalBots + totalVerifiedBots || 1;
								const pct = Math.round((v*100)/sum);
								return ` ${ctx.label}: ${v} (${pct}%)`;
							}
						}
					}
				}
			}
		});

		// 5) Turnstile Precision Chart
		const turnstileData = <?php echo wp_json_encode($turnstile_data); ?>;

		if (turnstileData && turnstileData.timeseries && turnstileData.timeseries.length > 0) {
			const tsTimeseries = turnstileData.timeseries;
			const tsLabels = tsTimeseries.map(i => fmtHHMM(i.time));
			const tsRedirects = tsTimeseries.map(i => i.redirect_count || 0);
			const tsPasses = tsTimeseries.map(i => i.pass_count || 0);
			// Failed = redirects - passed (people who didn't complete the challenge)
			const tsFails = tsTimeseries.map(i => Math.max(0, (i.redirect_count || 0) - (i.pass_count || 0)));
			const tsPrecision = tsTimeseries.map(i => i.precision || 0);

			// Bar chart: Passes vs Fails over time
			const turnstileBarCtx = document.getElementById('baskervilleTurnstileBar').getContext('2d');
			new Chart(turnstileBarCtx, {
				type: 'bar',
				data: {
					labels: tsLabels,
					datasets: [
						{
							label: '<?php echo esc_js(__('Passed (Humans)', 'baskerville')); ?>',
							data: tsPasses,
							stack: 'challenges',
							backgroundColor: '#4CAF50'
						},
						{
							label: '<?php echo esc_js(__('Failed (Bots)', 'baskerville')); ?>',
							data: tsFails,
							stack: 'challenges',
							backgroundColor: '#E91E63'
						}
					]
				},
				options: {
					responsive: true,
					maintainAspectRatio: true,
					interaction: { mode: 'index', intersect: false },
					scales: {
						x: { stacked: true, title: { display: true, text: '<?php echo esc_js(__('Time', 'baskerville')); ?>' } },
						y: { stacked: true, beginAtZero: true, title: { display: true, text: '<?php echo esc_js(__('Challenges', 'baskerville')); ?>' } }
					},
					plugins: {
						title: { display: true, text: '<?php echo esc_js(__('Turnstile Challenges', 'baskerville')); ?> — last ' + hours + 'h' },
						tooltip: {
							callbacks: {
								afterBody(items) {
									const idx = items[0].dataIndex;
									const redirects = tsRedirects[idx] || 0;
									const passes = tsPasses[idx] || 0;
									// Precision = % who did NOT pass
									const precision = redirects > 0 ? Math.round(((redirects - passes) * 100) / redirects) : 0;
									return ['<?php echo esc_js(__('Redirects:', 'baskerville')); ?> ' + redirects, '<?php echo esc_js(__('Precision:', 'baskerville')); ?> ' + precision + '%'];
								}
							}
						}
					}
				}
			});

			// Display total precision value
			document.getElementById('turnstilePrecisionValue').textContent = turnstileData.total_precision + '%';

			// Display stats - Failed = redirects - passed
			const totalFailed = Math.max(0, turnstileData.total_redirects - turnstileData.total_passes);
			document.getElementById('turnstileStats').innerHTML =
				'<strong><?php echo esc_js(__('Challenged:', 'baskerville')); ?></strong> ' + turnstileData.total_redirects + '<br>' +
				'<strong><?php echo esc_js(__('Passed:', 'baskerville')); ?></strong> ' + turnstileData.total_passes + '<br>' +
				'<strong><?php echo esc_js(__('Failed:', 'baskerville')); ?></strong> ' + totalFailed;
		} else {
			// No turnstile data
			document.getElementById('baskervilleTurnstileBar').parentElement.innerHTML = '<p class="baskerville-no-data"><?php echo esc_js(__('No Turnstile data available. Enable Turnstile challenge for borderline scores to see data here.', 'baskerville')); ?></p>';
			document.getElementById('turnstilePrecisionValue').textContent = '—';
			document.getElementById('turnstileStats').innerHTML = '<em><?php echo esc_js(__('No challenges recorded', 'baskerville')); ?></em>';
		}
	})();
	</script>
	<?php endif; ?>
	<?php
		} catch (Exception $e) {
			/* translators: %s is the error message */
		echo '<div class="notice notice-error"><p>' . sprintf(esc_html__('Charts Error: %s', 'baskerville'), esc_html($e->getMessage())) . '</p></div>';
		}
		?>

		<!-- IP Troubleshooting Section -->
		<div class="baskerville-ip-lookup">
			<h2 class="baskerville-ip-lookup-title">
				<span class="dashicons dashicons-search baskerville-icon-lg"></span>
				<?php esc_html_e('IP Troubleshooting', 'baskerville'); ?>
			</h2>
			<p class="baskerville-text-muted baskerville-mb-20">
				<?php esc_html_e('Enter an IP address to see its history: bans, block reasons, classifications, and more.', 'baskerville'); ?>
			</p>

			<div class="baskerville-ip-lookup-form">
				<input type="text" id="baskerville-ip-lookup" placeholder="<?php esc_attr_e('Enter IP address (e.g., 192.168.1.1)', 'baskerville'); ?>"
					   class="baskerville-ip-input">
				<button type="button" id="baskerville-ip-lookup-btn" class="button button-primary baskerville-btn-padded">
					<?php esc_html_e('Search', 'baskerville'); ?>
				</button>
			</div>

			<div id="baskerville-ip-results" class="baskerville-hidden">
				<!-- Results will be inserted here -->
			</div>
		</div>

		<script>
		jQuery(document).ready(function($) {
			$('#baskerville-ip-lookup-btn').on('click', function() {
				const ip = $('#baskerville-ip-lookup').val().trim();
				if (!ip) {
					alert('<?php echo esc_js(__('Please enter an IP address', 'baskerville')); ?>');
					return;
				}

				const $btn = $(this);
				const $results = $('#baskerville-ip-results');

				$btn.prop('disabled', true).text('<?php echo esc_js(__('Searching...', 'baskerville')); ?>');
				$results.html('<p class="baskerville-loading"><span class="dashicons dashicons-update baskerville-spinner"></span> <?php echo esc_js(__('Loading...', 'baskerville')); ?></p>').show();

				$.ajax({
					url: ajaxurl,
					type: 'POST',
					data: {
						action: 'baskerville_ip_lookup',
						ip: ip,
						_wpnonce: '<?php echo esc_js(wp_create_nonce('baskerville_ip_lookup')); ?>'
					},
					success: function(response) {
						$btn.prop('disabled', false).text('<?php echo esc_js(__('Search', 'baskerville')); ?>');

						if (response.success) {
							const data = response.data;
							let html = '';

							// Summary
							html += '<div class="baskerville-ip-result-box ' + (data.is_banned ? 'banned' : 'allowed') + '">';
							html += '<h3>' + (data.is_banned ? '🚫' : '✅') + ' <?php echo esc_js(__('IP:', 'baskerville')); ?> ' + $('<div>').text(ip).html() + '</h3>';
							html += '<p><strong><?php echo esc_js(__('Status:', 'baskerville')); ?></strong> ' + (data.is_banned ? '<?php echo esc_js(__('Currently BANNED', 'baskerville')); ?>' : '<?php echo esc_js(__('Not currently banned', 'baskerville')); ?>') + '</p>';
							if (data.country) {
								html += '<p><strong><?php echo esc_js(__('Country:', 'baskerville')); ?></strong> ' + $('<div>').text(data.country).html() + '</p>';
							}
							if (data.total_events > 0) {
								html += '<p><strong><?php echo esc_js(__('Total events:', 'baskerville')); ?></strong> ' + data.total_events + '</p>';
								html += '<p><strong><?php echo esc_js(__('Block events:', 'baskerville')); ?></strong> ' + data.block_events + '</p>';
							}
							html += '</div>';

							// Events table
							if (data.events && data.events.length > 0) {
								html += '<h3><?php echo esc_js(__('Recent Events (last 100)', 'baskerville')); ?></h3>';
								html += '<div class="baskerville-events-scroll">';
								html += '<table class="baskerville-events-table">';
								html += '<thead><tr>';
								html += '<th><?php echo esc_js(__('Time', 'baskerville')); ?></th>';
								html += '<th><?php echo esc_js(__('Classification', 'baskerville')); ?></th>';
								html += '<th><?php echo esc_js(__('Score', 'baskerville')); ?></th>';
								html += '<th><?php echo esc_js(__('Block Reason', 'baskerville')); ?></th>';
								html += '<th><?php echo esc_js(__('User Agent', 'baskerville')); ?></th>';
								html += '</tr></thead><tbody>';

								data.events.forEach(function(event) {
									const hasBlock = event.block_reason && event.block_reason !== '';
									const rowClass = hasBlock ? 'class="baskerville-row-blocked"' : '';
									html += '<tr ' + rowClass + '>';
									html += '<td class="baskerville-nowrap">' + $('<div>').text(event.timestamp).html() + '</td>';
									html += '<td><span class="baskerville-badge" style="background: ' + getClassColor(event.classification) + ';">' + $('<div>').text(event.classification || 'unknown').html() + '</span></td>';
									html += '<td class="baskerville-score-cell ' + (event.score >= 50 ? 'high' : 'low') + '">' + (event.score || 0) + '</td>';
									html += '<td class="' + (hasBlock ? 'baskerville-block-reason' : 'baskerville-text-muted') + '">' + $('<div>').text(event.block_reason || '-').html() + '</td>';
									html += '<td class="ua-cell" title="' + $('<div>').text(event.user_agent || '').html() + '">' + $('<div>').text((event.user_agent || '').substring(0, 50) + (event.user_agent && event.user_agent.length > 50 ? '...' : '')).html() + '</td>';
									html += '</tr>';
								});

								html += '</tbody></table></div>';
							} else {
								html += '<p class="baskerville-text-muted baskerville-italic"><?php echo esc_js(__('No events found for this IP address.', 'baskerville')); ?></p>';
							}

							$results.html(html);
						} else {
							$results.html('<div class="notice notice-error"><p>' + (response.data || '<?php echo esc_js(__('Error searching for IP', 'baskerville')); ?>') + '</p></div>');
						}
					},
					error: function() {
						$btn.prop('disabled', false).text('<?php echo esc_js(__('Search', 'baskerville')); ?>');
						$results.html('<div class="notice notice-error"><p><?php echo esc_js(__('Request failed. Please try again.', 'baskerville')); ?></p></div>');
					}
				});
			});

			// Allow Enter key to trigger search
			$('#baskerville-ip-lookup').on('keypress', function(e) {
				if (e.which === 13) {
					$('#baskerville-ip-lookup-btn').click();
				}
			});

			function getClassColor(classification) {
				const colors = {
					'bad_bot': '#f44336',
					'ai_bot': '#9c27b0',
					'bot': '#ff9800',
					'verified_bot': '#2196f3',
					'human': '#4caf50',
					'unknown': '#9e9e9e'
				};
				return colors[classification] || '#9e9e9e';
			}
		});
		</script>
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
			echo '<div class="notice notice-success"><p>' . esc_html__('IP Allow List saved successfully!', 'baskerville') . '</p></div>';
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
				echo '<div class="notice notice-success"><p>' . sprintf(esc_html__('Added %s to Allow List!', 'baskerville'), esc_html($current_ip)) . '</p></div>';
				$whitelist = $new_whitelist;
				$ips_array = $current_ips;
			} else {
				/* translators: %s is the IP address already in allow list */
				echo '<div class="notice notice-info"><p>' . sprintf(esc_html__('%s is already in the Allow List.', 'baskerville'), esc_html($current_ip)) . '</p></div>';
			}
		}
		?>
		<div class="baskerville-whitelist-tab">
			<h2><?php esc_html_e('IP Allow List', 'baskerville'); ?></h2>

			<div class="card baskerville-card-800">
				<p><?php esc_html_e('IP addresses in the Allow List bypass all firewall checks and will never be blocked by Baskerville.', 'baskerville'); ?></p>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
					<strong><?php esc_html_e('Your Current IP:', 'baskerville'); ?></strong>
					<code class="baskerville-code"><?php echo esc_html($current_ip); ?></code>

					<?php if (!in_array($current_ip, $ips_array, true) && $current_ip !== 'unknown'): ?>
						<form method="post" class="baskerville-inline-form">
							<?php wp_nonce_field('baskerville_whitelist_quick_add', 'baskerville_whitelist_quick_nonce'); ?>
							<button type="submit" name="baskerville_quick_add_ip" class="button button-secondary baskerville-valign-middle">
								➕ <?php esc_html_e('Add My IP', 'baskerville'); ?>
							</button>
						</form>
					<?php else: ?>
						<span class="baskerville-text-success baskerville-ml-10">✅ <?php esc_html_e('Already in Allow List', 'baskerville'); ?></span>
					<?php endif; ?>
				</div>

				<form method="post">
					<?php wp_nonce_field('baskerville_whitelist_save', 'baskerville_whitelist_nonce'); ?>

					<table class="form-table">
						<tr>
							<th scope="row">
								<label for="baskerville_ip_whitelist"><?php esc_html_e('Allowed IPs', 'baskerville'); ?></label>
							</th>
							<td>
								<textarea
									name="baskerville_ip_whitelist"
									id="baskerville_ip_whitelist"
									rows="10"
									class="large-text code baskerville-font-mono"
								><?php echo esc_textarea($whitelist); ?></textarea>

								<p class="description">
									<?php esc_html_e('Enter one IP address per line. You can also separate IPs with commas or spaces.', 'baskerville'); ?><br>
									<strong><?php esc_html_e('Supported formats:', 'baskerville'); ?></strong><br>
									• IPv4: <code>192.168.1.1</code><br>
									• IPv6: <code>2001:0db8:85a3::8a2e:0370:7334</code><br>
									• Multiple per line: <code>1.2.3.4, 5.6.7.8</code>
								</p>
							</td>
						</tr>
					</table>

					<?php submit_button(__('Save Allow List', 'baskerville'), 'primary', 'baskerville_save_whitelist'); ?>
				</form>
			</div>

			<?php if (!empty($ips_array)): ?>
			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('IPs in Allow List', 'baskerville'); ?> (<?php echo count($ips_array); ?>)</h3>
				<table class="widefat striped baskerville-mt-10">
					<thead>
						<tr>
							<th><?php esc_html_e('IP Address', 'baskerville'); ?></th>
							<th><?php esc_html_e('Status', 'baskerville'); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ($ips_array as $ip): ?>
						<tr>
							<td>
								<code class="baskerville-text-xs"><?php echo esc_html($ip); ?></code>
								<?php if ($ip === $current_ip): ?>
									<span class="baskerville-text-primary-bold"> (<?php esc_html_e('Your IP', 'baskerville'); ?>)</span>
								<?php endif; ?>
							</td>
							<td>
								<?php if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)): ?>
									<span class="baskerville-color-success">✓ <?php esc_html_e('Valid IPv4', 'baskerville'); ?></span>
								<?php elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)): ?>
									<span class="baskerville-color-success">✓ <?php esc_html_e('Valid IPv6', 'baskerville'); ?></span>
								<?php else: ?>
									<span class="baskerville-desc-danger">✗ <?php esc_html_e('Invalid IP', 'baskerville'); ?></span>
								<?php endif; ?>
							</td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php endif; ?>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Use Cases', 'baskerville'); ?></h3>
				<ul class="baskerville-list-spaced">
					<li><strong><?php esc_html_e('Load Testing:', 'baskerville'); ?></strong> <?php esc_html_e('Add your server IP to run Apache Bench or similar tools', 'baskerville'); ?></li>
					<li><strong><?php esc_html_e('Office Network:', 'baskerville'); ?></strong> <?php esc_html_e('Add your company IP to ensure team members never get blocked', 'baskerville'); ?></li>
					<li><strong><?php esc_html_e('Development:', 'baskerville'); ?></strong> <?php esc_html_e('Add localhost (127.0.0.1) if testing locally', 'baskerville'); ?></li>
					<li><strong><?php esc_html_e('Monitoring Services:', 'baskerville'); ?></strong> <?php esc_html_e('Add uptime monitors or site crawlers', 'baskerville'); ?></li>
					<li><strong><?php esc_html_e('API Clients:', 'baskerville'); ?></strong> <?php esc_html_e('Add IPs of your API consumers', 'baskerville'); ?></li>
				</ul>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-sm baskerville-alert-mt">
					<strong>💡 <?php esc_html_e('Tip:', 'baskerville'); ?></strong>
					<?php esc_html_e('IPs in the Allow List completely bypass the firewall. For better security, consider using GeoIP Allow List or verified crawler detection instead when possible.', 'baskerville'); ?>
				</div>
			</div>
		</div>
		<?php
	}

	/* ===== Performance Tab ===== */
	private function render_performance_tab() {
		?>
		<div class="baskerville-performance-tab">
			<h2><?php esc_html_e('Performance Benchmarks', 'baskerville'); ?></h2>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Internal Benchmarks', 'baskerville'); ?></h3>
				<p><?php esc_html_e('Run internal performance tests to measure the overhead of various Baskerville operations.', 'baskerville'); ?></p>

				<table class="widefat baskerville-mb-15">
					<thead>
						<tr>
							<th><?php esc_html_e('Test', 'baskerville'); ?></th>
							<th><?php esc_html_e('Description', 'baskerville'); ?></th>
							<th><?php esc_html_e('Action', 'baskerville'); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><strong><?php esc_html_e('GeoIP Lookup', 'baskerville'); ?></strong></td>
							<td><?php esc_html_e('Measure time to perform 100 GeoIP lookups', 'baskerville'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="geoip">
									<?php esc_html_e('Run Test', 'baskerville'); ?>
								</button>
								<span class="benchmark-result" data-test="geoip"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('AI/UA Classification', 'baskerville'); ?></strong></td>
							<td><?php esc_html_e('Measure time to classify 100 user agents', 'baskerville'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="ai-ua">
									<?php esc_html_e('Run Test', 'baskerville'); ?>
								</button>
								<span class="benchmark-result" data-test="ai-ua"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Cache Operations', 'baskerville'); ?></strong></td>
							<td><?php esc_html_e('Measure cache set/get performance (APCu: 1000 ops, File: 100 ops)', 'baskerville'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="cache">
									<?php esc_html_e('Run Test', 'baskerville'); ?>
								</button>
								<span class="benchmark-result" data-test="cache"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Full Firewall Check', 'baskerville'); ?></strong></td>
							<td><?php esc_html_e('Simulate 100 complete firewall checks', 'baskerville'); ?></td>
							<td>
								<button type="button" class="button benchmark-btn" data-test="firewall">
									<?php esc_html_e('Run Test', 'baskerville'); ?>
								</button>
								<span class="benchmark-result" data-test="firewall"></span>
							</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Run All Tests', 'baskerville'); ?></strong></td>
							<td><?php esc_html_e('Execute all benchmarks sequentially', 'baskerville'); ?></td>
							<td>
								<button type="button" class="button button-primary benchmark-btn" data-test="all">
									<?php esc_html_e('Run All', 'baskerville'); ?>
								</button>
								<span class="benchmark-result" data-test="all"></span>
							</td>
						</tr>
					</tbody>
				</table>
			</div>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('External Load Testing', 'baskerville'); ?></h3>

				<h4><?php esc_html_e('Method 1: File Logging Mode (Recommended)', 'baskerville'); ?> ✅</h4>
				<p><?php esc_html_e('Test with firewall ACTIVE but using fast file logging:', 'baskerville'); ?></p>
				<ol class="baskerville-list-spaced">
					<li><?php esc_html_e('Go to Settings tab → Select "File Logging" mode', 'baskerville'); ?></li>
					<li><?php esc_html_e('Run your tests - firewall will process requests normally', 'baskerville'); ?></li>
					<li><?php esc_html_e('Deactivate plugin and test again to compare', 'baskerville'); ?></li>
				</ol>
				<p class="baskerville-color-info"><strong><?php esc_html_e('Expected overhead: ~50-70ms (5%)', 'baskerville'); ?></strong></p>

				<h4 class="baskerville-mt-20"><?php esc_html_e('Method 2: Add Your IP to Allow List', 'baskerville'); ?></h4>
				<p><?php esc_html_e('Test with firewall BYPASSED (shows minimum overhead):', 'baskerville'); ?></p>
				<p><?php esc_html_e('Go to IP Allow List tab → Click "Add My IP" button → Run your tests', 'baskerville'); ?></p>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
					<strong><?php esc_html_e('Your Current IP:', 'baskerville'); ?></strong>
					<code class="baskerville-code">
						<?php
						echo esc_html(sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? 'unknown')));
						?>
					</code>
				</div>
				<p class="baskerville-color-success"><strong><?php esc_html_e('Expected overhead: ~0-5ms (0%)', 'baskerville'); ?></strong></p>

				<h4 class="baskerville-mt-20"><?php esc_html_e('Testing Commands', 'baskerville'); ?></h4>
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

				<h4 class="baskerville-mt-20"><?php esc_html_e('Expected Performance by Mode', 'baskerville'); ?></h4>
				<table class="widefat baskerville-mt-10">
					<thead>
						<tr>
							<th><?php esc_html_e('Logging Mode', 'baskerville'); ?></th>
							<th><?php esc_html_e('Overhead', 'baskerville'); ?></th>
							<th><?php esc_html_e('Analytics', 'baskerville'); ?></th>
							<th><?php esc_html_e('Best For', 'baskerville'); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><strong><?php esc_html_e('File Logging', 'baskerville'); ?></strong></td>
							<td class="baskerville-color-success">~50-70ms (5%)</td>
							<td>✅ <?php esc_html_e('Full (5min delay)', 'baskerville'); ?></td>
							<td><?php esc_html_e('Production', 'baskerville'); ?> ✅</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Disabled', 'baskerville'); ?></strong></td>
							<td class="baskerville-color-success">~0ms (0%)</td>
							<td>❌ <?php esc_html_e('None', 'baskerville'); ?></td>
							<td><?php esc_html_e('Testing/Dev', 'baskerville'); ?></td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('Database', 'baskerville'); ?></strong></td>
							<td class="baskerville-color-warning">~500ms (36%)</td>
							<td>✅ <?php esc_html_e('Instant', 'baskerville'); ?></td>
							<td><?php esc_html_e('VPS only', 'baskerville'); ?> ⚠️</td>
						</tr>
						<tr>
							<td><strong><?php esc_html_e('IP in Allow List', 'baskerville'); ?></strong></td>
							<td class="baskerville-color-success">~0-5ms (0%)</td>
							<td>✅ <?php esc_html_e('Partial', 'baskerville'); ?></td>
							<td><?php esc_html_e('Load testing', 'baskerville'); ?></td>
						</tr>
					</tbody>
				</table>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-sm baskerville-alert-mt">
					<strong>💡 <?php esc_html_e('Recommendation:', 'baskerville'); ?></strong>
					<?php esc_html_e('Use <strong>File Logging</strong> mode (default) for production. It provides full analytics with minimal overhead (~5%), perfect for shared hosting.', 'baskerville'); ?>
				</div>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm baskerville-alert-mt">
					<strong>⚠️ <?php esc_html_e('Note:', 'baskerville'); ?></strong>
					<?php esc_html_e('Absolute response times vary by server, but overhead percentage is consistent. Focus on the % difference, not absolute milliseconds.', 'baskerville'); ?>
				</div>
			</div>

			<div class="card baskerville-card-800">
				<h3><?php esc_html_e('Performance Tips', 'baskerville'); ?></h3>
				<ul class="baskerville-list-spaced">
					<li><?php esc_html_e('Enable APCu for faster caching (file-based cache is slower)', 'baskerville'); ?></li>
					<li><?php esc_html_e('Use NGINX GeoIP2 module for fastest country detection', 'baskerville'); ?></li>
					<li><?php esc_html_e('Allow verified crawlers to reduce unnecessary checks', 'baskerville'); ?></li>
					<li><?php esc_html_e('The firewall only runs on public HTML pages (not wp-admin, REST API, or AJAX)', 'baskerville'); ?></li>
					<li><?php esc_html_e('Database writes are batched and use prepared statements', 'baskerville'); ?></li>
				</ul>
			</div>
		</div>

		<script type="text/javascript">
		jQuery(document).ready(function($) {
			$('.benchmark-btn').on('click', function() {
				var $btn = $(this);
				var test = $btn.data('test');
				var $result = $('.benchmark-result[data-test="' + test + '"]');

				$btn.prop('disabled', true);
				$result.removeClass('success error').addClass('loading').text('<?php esc_html_e('Running...', 'baskerville'); ?>');

				$.ajax({
					url: ajaxurl,
					type: 'POST',
					data: {
						action: 'baskerville_run_benchmark',
						nonce: '<?php echo esc_js(wp_create_nonce('baskerville_benchmark')); ?>',
						test: test
					},
					success: function(response) {
						if (response.success) {
							$result.removeClass('loading').addClass('success').html(response.data.message);
						} else {
							$result.removeClass('loading').addClass('error').text(response.data.message || '<?php esc_html_e('Error', 'baskerville'); ?>');
						}
					},
					error: function() {
						$result.removeClass('loading').addClass('error').text('<?php esc_html_e('AJAX error', 'baskerville'); ?>');
					},
					complete: function() {
						$btn.prop('disabled', false);
					}
				});
			});
		});
		</script>
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
			<h2><?php esc_html_e('API Protection Settings', 'baskerville'); ?></h2>

			<!-- How API Detection Works -->
			<div class="card baskerville-card-1000">
				<h3><?php esc_html_e('How API Auto-Detection Works', 'baskerville'); ?></h3>

				<p><?php esc_html_e('Baskerville automatically detects API requests and applies special protection rules. API requests BYPASS the firewall (no 403 bans, no burst protection) and only use rate limiting.', 'baskerville'); ?></p>

				<h4><?php esc_html_e('Detection Methods:', 'baskerville'); ?></h4>

				<div class="baskerville-card">
					<strong>1. <?php esc_html_e('Content-Type Headers:', 'baskerville'); ?></strong>
					<p class="baskerville-api-desc">
						<code>application/json</code>, <code>application/xml</code>, <code>application/graphql</code>,
						<code>application/ld+json</code>, <code>multipart/form-data</code>
					</p>
				</div>

				<div class="baskerville-card">
					<strong>2. <?php esc_html_e('URL Patterns:', 'baskerville'); ?></strong>
					<p class="baskerville-api-desc">
						<code>/api/</code>, <code>/v1/</code>, <code>/v2/</code>, <code>/v3/</code>,
						<code>/rest/</code>, <code>/graphql/</code>, <code>/wp-json/</code>,
						<code>/webhook/</code>, <code>/payment/</code>, <code>/checkout/</code>,
						<code>/auth/</code>, <code>/oauth/</code>, <code>/token/</code>
					</p>
				</div>

				<div class="baskerville-card">
					<strong>3. <?php esc_html_e('Accept Headers:', 'baskerville'); ?></strong>
					<p class="baskerville-api-desc">
						<?php esc_html_e('Requests with Accept header requesting JSON or XML format', 'baskerville'); ?>
					</p>
				</div>

				<div class="baskerville-alert baskerville-alert-success baskerville-alert-lg">
					<strong>✓ <?php esc_html_e('What happens to API requests:', 'baskerville'); ?></strong>
					<ul class="baskerville-list-indent">
						<li><?php esc_html_e('Bypass all firewall rules (GeoIP, burst protection, bot detection)', 'baskerville'); ?></li>
						<li><?php esc_html_e('Never receive 403 Forbidden responses', 'baskerville'); ?></li>
						<li><?php esc_html_e('Only subject to rate limiting (429 Too Many Requests)', 'baskerville'); ?></li>
						<li><?php esc_html_e('IPs in Allow List bypass rate limiting completely', 'baskerville'); ?></li>
					</ul>
				</div>
			</div>

			<!-- Rate Limiting Settings -->
			<div class="card baskerville-card-1000">
				<h3><?php esc_html_e('API Rate Limiting', 'baskerville'); ?></h3>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg">
					<strong><?php esc_html_e('How Rate Limiting Works:', 'baskerville'); ?></strong>
					<p>
						<?php esc_html_e('Rate limiting counts requests per IP address in a sliding time window. When the limit is exceeded, API requests receive HTTP 429 (Too Many Requests) with a Retry-After header.', 'baskerville'); ?>
					</p>
					<p>
						<strong><?php esc_html_e('Example:', 'baskerville'); ?></strong>
						<?php esc_html_e('100 requests / 60 seconds means each IP can make maximum 100 API requests per minute. The 101st request returns 429 error.', 'baskerville'); ?>
					</p>
				</div>

				<table class="form-table">
					<tr>
						<th scope="row">
							<label for="api_rate_limit_enabled">
								<?php esc_html_e('Enable Rate Limiting', 'baskerville'); ?>
							</label>
						</th>
						<td>
							<label>
								<input type="checkbox"
									   id="api_rate_limit_enabled"
									   name="baskerville_settings[api_rate_limit_enabled]"
									   value="1"
									   <?php checked($rate_limit_enabled, true); ?> />
								<?php esc_html_e('Enable rate limiting for REST API endpoints', 'baskerville'); ?>
							</label>
							<p class="description">
								<?php esc_html_e('When enabled, API requests exceeding the limit will receive a 429 Too Many Requests response.', 'baskerville'); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="api_rate_limit_requests">
								<?php esc_html_e('Request Limit', 'baskerville'); ?>
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
							<?php esc_html_e('requests', 'baskerville'); ?>
							<p class="description">
								<?php esc_html_e('Maximum number of requests allowed per IP address.', 'baskerville'); ?>
							</p>
						</td>
					</tr>

					<tr>
						<th scope="row">
							<label for="api_rate_limit_window">
								<?php esc_html_e('Time Window', 'baskerville'); ?>
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
							<?php esc_html_e('seconds', 'baskerville'); ?>
							<p class="description">
								<?php esc_html_e('Time window for the rate limit (60 seconds = 1 minute).', 'baskerville'); ?>
							</p>
						</td>
					</tr>
				</table>

				<div class="baskerville-alert baskerville-alert-info baskerville-alert-lg">
					<strong><?php esc_html_e('Current Configuration:', 'baskerville'); ?></strong>
					<?php if ($rate_limit_enabled): ?>
						<p class="baskerville-mt-5 baskerville-mb-0">
							<?php
							echo sprintf(
								/* translators: %1$d is number of requests, %2$d is time in seconds */
								esc_html__('Rate limiting is ENABLED: %1$d requests per %2$d seconds per IP address', 'baskerville'),
								esc_attr($rate_limit_requests),
								esc_attr($rate_limit_window)
							);
							?>
						</p>
					<?php else: ?>
						<p class="baskerville-mt-5 baskerville-mb-0 baskerville-text-danger">
							<?php esc_html_e('Rate limiting is DISABLED: API endpoints have no rate limits', 'baskerville'); ?>
						</p>
					<?php endif; ?>
				</div>

				<div class="baskerville-alert baskerville-alert-warning baskerville-alert-lg">
					<strong>💡 <?php esc_html_e('Recommended Settings:', 'baskerville'); ?></strong>
					<ul class="baskerville-my-10">
						<li><strong><?php esc_html_e('Low Traffic:', 'baskerville'); ?></strong> 100 requests/60s</li>
						<li><strong><?php esc_html_e('Medium Traffic:', 'baskerville'); ?></strong> 500 requests/60s</li>
						<li><strong><?php esc_html_e('High Traffic:', 'baskerville'); ?></strong> 1000 requests/60s</li>
					</ul>
					<p class="baskerville-mt-5 baskerville-mb-0">
						<?php esc_html_e('IPs in the Allow List bypass rate limiting completely.', 'baskerville'); ?>
					</p>
				</div>

				<p class="submit">
					<input type="submit" name="submit" id="submit" class="button button-primary" value="<?php esc_attr_e('Save API Settings', 'baskerville'); ?>">
				</p>
			</div>
		</div>
		<?php
	}

	public function ajax_run_benchmark() {
		try {
			check_ajax_referer('baskerville_benchmark', 'nonce');

			if (!current_user_can('manage_options')) {
				wp_send_json_error(array('message' => esc_html__('Insufficient permissions.', 'baskerville')));
				return;
			}

			$test = isset($_POST['test']) ? sanitize_text_field(wp_unslash($_POST['test'])) : '';

			if (empty($test)) {
				wp_send_json_error(array('message' => esc_html__('No test specified.', 'baskerville')));
				return;
			}

			// Ensure classes are loaded
			if (!class_exists('Baskerville_Core')) {
				wp_send_json_error(array('message' => esc_html__('Baskerville_Core class not found.', 'baskerville')));
				return;
			}

			$core = new Baskerville_Core();
			$aiua = null;

			// Only load AI_UA if needed
			if (in_array($test, array('ai-ua', 'firewall', 'all'), true)) {
				if (!class_exists('Baskerville_AI_UA')) {
					wp_send_json_error(array('message' => esc_html__('Baskerville_AI_UA class not found.', 'baskerville')));
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
					$message .= '<strong>GeoIP:</strong> ' . esc_html($results['geoip']['message']) . '<br>';
					$message .= '<strong>AI/UA:</strong> ' . esc_html($results['ai-ua']['message']) . '<br>';
					$message .= '<strong>Cache:</strong> ' . esc_html($results['cache']['message']) . '<br>';
					$message .= '<strong>Firewall:</strong> ' . esc_html($results['firewall']['message']);
					$message .= '</div>';

					wp_send_json_success(array(
						'message' => $message,
						'results' => $results
					));
					return;

				default:
					/* translators: %s is the invalid test type name */
				wp_send_json_error(array('message' => sprintf(esc_html__('Invalid test type: %s', 'baskerville'), esc_html($test))));
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
			'message' => sprintf(esc_html__('Benchmark failed: %s', 'baskerville'), $e->getMessage()),
				'file' => basename($e->getFile()),
				'line' => $e->getLine()
			));
		} catch (Error $e) {
			// error_log('Baskerville benchmark fatal error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
			wp_send_json_error(array(
				/* translators: %s is the error message */
			'message' => sprintf(esc_html__('Fatal error: %s', 'baskerville'), $e->getMessage()),
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
			'Googlebot/2.1 (+http://www.google.com/bot.html)',
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
		<h3 class="baskerville-subsection-title">🍯 <?php esc_html_e('Honeypot Trap', 'baskerville'); ?></h3>
		<p class="description">
			<?php esc_html_e('Catch AI bots accessing hidden links', 'baskerville'); ?>
		</p>
		<label>
			<input type="checkbox"
				   name="baskerville_settings[honeypot_enabled]"
				   value="1"
				   <?php checked($enabled, true); ?> />
			<?php esc_html_e('Enable honeypot trap', 'baskerville'); ?>
		</label>
		<p class="description">
			<?php esc_html_e('Adds a hidden link to your site footer that is invisible to humans but visible to AI crawlers in HTML.', 'baskerville'); ?><br>
			<?php esc_html_e('When an IP accesses this link, it is immediately marked as an AI bot.', 'baskerville'); ?><br>
			<strong><?php esc_html_e('Honeypot URL:', 'baskerville'); ?></strong> <code><?php echo esc_html(home_url('/ai-training-data/')); ?></code><br>
			<em class="baskerville-desc-danger"><?php esc_html_e('⚠️ The URL name "ai-training-data" is designed to attract AI bots looking for training content!', 'baskerville'); ?></em><br>
			<strong class="baskerville-desc-danger">⚠️ IMPORTANT:</strong> After enabling, go to
			<a href="<?php echo esc_url(admin_url('options-permalink.php')); ?>" target="_blank">Settings → Permalinks</a>
			and click "Save Changes" to activate the honeypot URL!
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
			<?php esc_html_e('Ban IPs that trigger honeypot', 'baskerville'); ?>
		</label>
		<p class="description">
			<?php esc_html_e('When enabled, IPs accessing the honeypot will be banned for 24 hours.', 'baskerville'); ?><br>
			<?php esc_html_e('When disabled, the visit is still logged as AI bot.', 'baskerville'); ?>
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
			<h4 class="baskerville-mt-0"><?php esc_html_e('What is Burst Protection?', 'baskerville'); ?></h4>
			<p><?php esc_html_e('Burst protection prevents abuse by blocking IPs that make too many requests too quickly. When the Master Switch is ON, burst protection will automatically block suspicious traffic patterns.', 'baskerville'); ?></p>

			<p><?php esc_html_e('When an IP exceeds the threshold, it receives a 403 Forbidden response and is temporarily banned. All burst types are counted separately per IP address using sliding time windows.', 'baskerville'); ?></p>

			<strong><?php esc_html_e('4 Types of Burst Protection:', 'baskerville'); ?></strong>
			<table class="baskerville-burst-table">
				<thead>
					<tr>
						<th><?php esc_html_e('Type', 'baskerville'); ?></th>
						<th><?php esc_html_e('Trigger Condition', 'baskerville'); ?></th>
						<th><?php esc_html_e('Purpose', 'baskerville'); ?></th>
					</tr>
				</thead>
				<tbody>
					<tr>
						<td><strong><?php esc_html_e('No-Cookie Burst', 'baskerville'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s without valid cookie', 'baskerville'); ?>
						</td>
						<td><?php esc_html_e('Blocks bots that don\'t accept cookies', 'baskerville'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('No-JS Burst', 'baskerville'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nojs_threshold); ?> <?php esc_html_e('requests', 'baskerville'); ?>/<?php echo esc_html($nojs_window); ?><?php esc_html_e('s without JavaScript', 'baskerville'); ?>
						</td>
						<td><?php esc_html_e('Blocks bots that don\'t execute JavaScript', 'baskerville'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Non-Browser UA Burst', 'baskerville'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s with non-browser User-Agent', 'baskerville'); ?>
						</td>
						<td><?php esc_html_e('Blocks scripts (curl, wget, python-requests, etc.)', 'baskerville'); ?></td>
					</tr>
					<tr>
						<td><strong><?php esc_html_e('Bad Bot Burst', 'baskerville'); ?></strong></td>
						<td>
							&gt;<?php echo esc_html($nocookie_threshold); ?> <?php esc_html_e('requests', 'baskerville'); ?>/<?php echo esc_html($nocookie_window); ?><?php esc_html_e('s for classified bad bots', 'baskerville'); ?>
						</td>
						<td><?php esc_html_e('Aggressive blocking for known malicious bots', 'baskerville'); ?></td>
					</tr>
				</tbody>
			</table>

			<div class="baskerville-alert baskerville-alert-warning baskerville-alert-sm">
				<strong>💡 <?php esc_html_e('How it works:', 'baskerville'); ?></strong>
				<ul class="baskerville-list-spaced">
					<li><?php esc_html_e('Each burst type is counted separately per IP address', 'baskerville'); ?></li>
					<li><?php esc_html_e('Uses sliding time windows (not fixed intervals)', 'baskerville'); ?></li>
					<li><?php esc_html_e('Verified crawlers (Google, Bing, etc.) bypass all burst protection', 'baskerville'); ?></li>
					<li><?php esc_html_e('IPs in Allow List bypass all burst protection', 'baskerville'); ?></li>
				</ul>
			</div>

			<div class="baskerville-danger-box">
				<strong>⚠️ <?php esc_html_e('For Testing:', 'baskerville'); ?></strong>
				<?php esc_html_e('If you\'re testing with scripts or non-browser tools, add your IP to the', 'baskerville'); ?>
				<strong><?php esc_html_e('IP Allow List', 'baskerville'); ?></strong>
				<?php esc_html_e('tab to bypass all protection.', 'baskerville'); ?>
			</div>
		</div>

		<!-- Burst Protection Thresholds Configuration -->
		<div class="baskerville-form-container">
			<h4 class="baskerville-mt-0"><?php esc_html_e('Burst Protection Thresholds', 'baskerville'); ?></h4>
			<p class="description"><?php esc_html_e('Configure the thresholds for each burst protection type. Lower values = more aggressive protection.', 'baskerville'); ?></p>

			<table class="form-table baskerville-mt-20">
				<tr>
					<th scope="row" colspan="2">
						<strong><?php esc_html_e('No-Cookie & Non-Browser UA Burst', 'baskerville'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="nocookie_threshold">
							<?php esc_html_e('Request Limit', 'baskerville'); ?>
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
						<?php esc_html_e('requests per', 'baskerville'); ?>
						<input type="number"
							   id="nocookie_window"
							   name="baskerville_nocookie_window_sec"
							   value="<?php echo esc_attr($nocookie_window); ?>"
							   min="10"
							   max="3600"
							   class="small-text" />
						<?php esc_html_e('seconds', 'baskerville'); ?>
						<p class="description">
							<?php esc_html_e('Default: 10 requests / 60 seconds. Applies to no-cookie, non-browser UA, and bad bot burst types.', 'baskerville'); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row" colspan="2" class="baskerville-form-section-header">
						<strong><?php esc_html_e('No-JavaScript Burst', 'baskerville'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="nojs_threshold">
							<?php esc_html_e('Request Limit', 'baskerville'); ?>
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
						<?php esc_html_e('requests per', 'baskerville'); ?>
						<input type="number"
							   id="nojs_window"
							   name="baskerville_nojs_window_sec"
							   value="<?php echo esc_attr($nojs_window); ?>"
							   min="10"
							   max="3600"
							   class="small-text" />
						<?php esc_html_e('seconds', 'baskerville'); ?>
						<p class="description">
							<?php esc_html_e('Default: 20 requests / 60 seconds. Applies when JavaScript fingerprint is not received.', 'baskerville'); ?>
						</p>
					</td>
				</tr>

				<tr>
					<th scope="row" colspan="2" class="baskerville-form-section-header">
						<strong><?php esc_html_e('Ban Duration', 'baskerville'); ?></strong>
					</th>
				</tr>
				<tr>
					<td class="baskerville-indent">
						<label for="ban_ttl">
							<?php esc_html_e('Ban TTL', 'baskerville'); ?>
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
						<?php esc_html_e('seconds', 'baskerville'); ?>
						<p class="description">
							<?php esc_html_e('Default: 600 seconds (10 minutes). How long to ban IPs that trigger burst protection.', 'baskerville'); ?>
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
			wp_send_json_error(array('message' => esc_html__( 'Insufficient permissions.', 'baskerville' )));
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
				__('Successfully imported %d records from log files', 'baskerville'),
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
			wp_send_json_error(esc_html__('Security check failed.', 'baskerville'));
		}

		// Check permissions
		if (!current_user_can('manage_options')) {
			wp_send_json_error(esc_html__('Insufficient permissions.', 'baskerville'));
		}

		// Get and validate IP
		$ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
		if (!$ip || !filter_var($ip, FILTER_VALIDATE_IP)) {
			wp_send_json_error(esc_html__('Invalid IP address.', 'baskerville'));
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