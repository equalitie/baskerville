<?php
/**
 * Plugin Name: Baskerville
 * Plugin URI: https://wordpress.org/plugins/baskerville/
 * Description: A WordPress plugin by Equalitie.
 * Version: 1.0.0
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: eQualitie
 * Author URI: https://equalitie.org
 * License: GPL v3
 * Text Domain: baskerville
 */

if (!defined('ABSPATH')) exit;

define('BASKERVILLE_VERSION', '1.0.0');
define('BASKERVILLE_PLUGIN_FILE', __FILE__);
define('BASKERVILLE_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('BASKERVILLE_PLUGIN_URL',  plugin_dir_url(__FILE__));
define('BASKERVILLE_DEBUG', defined('WP_DEBUG') && WP_DEBUG);
define('BASKERVILLE_DEFAULT_RETENTION_DAYS', 14);

// includes
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-core.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-ai-ua.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-stats.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-firewall.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-rest.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-honeypot.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-maxmind-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'admin/class-baskerville-admin.php';

// Add custom cron interval for file logging (1 minute)
add_filter('cron_schedules', function($schedules) {
	$schedules['baskerville_1min'] = array(
		'interval' => 60, // 1 minute in seconds
		'display'  => __('Every Minute (Baskerville)', 'baskerville')
	);
	return $schedules;
});

add_action('plugins_loaded', function () {
	// basic services
	$core  = new Baskerville_Core();
	$aiua  = new Baskerville_AI_UA($core);       // AI_UA should receive $core in constructor
	$stats = new Baskerville_Stats($core, $aiua); // Stats receives Core and AI_UA

	// pre-DB firewall (MUST run IMMEDIATELY, before any other hooks)
	// This runs directly in plugins_loaded to catch requests as early as possible
	$fw = new Baskerville_Firewall($core, $stats, $aiua);
	$fw->pre_db_firewall();

	// i18n + frontend JS + widget toggle
	add_action('init', [$core, 'init']);                         // load_plugin_textdomain + add_fingerprinting_script
	add_action('init', [$core, 'handle_widget_toggle'], 0);      // earlier — to set/remove cookie

	// early identifier setup (before output)
	add_action('send_headers', [$core, 'ensure_baskerville_cookie'], 0);

	// logging public HTML page visits
	add_action('template_redirect', [$stats, 'log_page_visit'], 0);

	// REST API
	$rest = new Baskerville_REST($core, $stats, $aiua);
	add_action('rest_api_init', [$rest, 'register_routes']);

	// Honeypot for AI bot detection
	$honeypot = new Baskerville_Honeypot($core, $stats, $aiua);
	$honeypot->init();

	// periodic statistics cleanup
	add_action('baskerville_cleanup_stats', [$stats, 'cleanup_old_stats']);

	// periodic cache file cleanup
	add_action('baskerville_cleanup_cache', [$core, 'fc_cleanup_old_files']);

	// periodic log file import to DB (file logging mode) - every minute for faster blocking
	add_action('baskerville_process_log_files', [$stats, 'process_log_files_to_db']);

	// periodic old log file cleanup
	add_action('baskerville_cleanup_log_files', [$stats, 'cleanup_old_log_files']);

	// admin
	if (is_admin()) {
		new Baskerville_Admin();
	}
});

// activation/deactivation
register_activation_hook(__FILE__,   ['Baskerville_Installer', 'activate']);
register_deactivation_hook(__FILE__, ['Baskerville_Installer', 'deactivate']);
