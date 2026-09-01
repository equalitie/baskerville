<?php
/**
 * Plugin Name: Baskerville AI Security
 * Plugin URI: https://wordpress.org/plugins/baskerville-ai-security/
 * Description: Advanced WordPress security plugin with AI bot detection, GeoIP access control, and Cloudflare Turnstile integration.
 * Version: 1.0.5
 * Requires at least: 6.2
 * Requires PHP: 7.4
 * Author: eQualitie
 * Author URI: https://equalitie.org
 * License: GPL v3
 * Text Domain: baskerville-ai-security
 */

if (!defined('ABSPATH')) exit;

define('BASKERVILLE_VERSION', '1.0.5');
define('BASKERVILLE_PLUGIN_FILE', __FILE__);
define('BASKERVILLE_PLUGIN_PATH', plugin_dir_path(__FILE__));
define('BASKERVILLE_PLUGIN_URL',  plugin_dir_url(__FILE__));
define('BASKERVILLE_DEBUG', defined('WP_DEBUG') && WP_DEBUG);
define('BASKERVILLE_DEFAULT_RETENTION_DAYS', 14);

if ( ! function_exists( 'wpsec_log' ) ) {
	function wpsec_log( string $msg ): void {
		if ( BASKERVILLE_DEBUG ) {
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log( $msg );
		}
	}
}

// includes
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-core.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-ai-ua.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-stats.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-firewall.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-rest.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-honeypot.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-maxmind-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-turnstile.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-altcha.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-ai-bots.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-cloud.php';
require_once BASKERVILLE_PLUGIN_PATH . 'admin/class-baskerville-admin.php';

// Add custom cron intervals
add_filter('cron_schedules', function($schedules) {
	$schedules['baskerville_1min'] = array(
		'interval' => 60, // 1 minute in seconds
		'display'  => __('Every Minute (Baskerville)', 'baskerville-ai-security')
	);
	$schedules['baskerville_5min'] = array(
		'interval' => 300, // 5 minutes in seconds
		'display'  => __('Every 5 Minutes (Baskerville)', 'baskerville-ai-security')
	);
	$schedules['baskerville_weekly'] = array(
		'interval' => 604800, // 7 days in seconds
		'display'  => __('Weekly (Baskerville)', 'baskerville-ai-security')
	);
	return $schedules;
});

add_action('plugins_loaded', function () {
	// basic services
	$core  = new Baskerville_Core();
	$aiua  = new Baskerville_AI_UA($core);       // AI_UA should receive $core in constructor
	$stats = new Baskerville_Stats($core, $aiua); // Stats receives Core and AI_UA

	// Challenge provider (Altcha by default, Cloudflare Turnstile as option)
	$options            = get_option('baskerville_settings', array());
	$challenge_provider = isset($options['challenge_provider']) ? $options['challenge_provider'] : 'altcha';
	if ($challenge_provider === 'cloudflare_turnstile') {
		$turnstile = new Baskerville_Turnstile($core, $stats);
	} else {
		$turnstile = new Baskerville_Altcha($core, $stats);
	}
	$GLOBALS['baskerville_turnstile'] = $turnstile;

	// Cache integration: when Under Attack Mode is ON, configure cache plugins to
	// create separate cache variants per baskerville_pass cookie.
	// - Visitors WITH baskerville_pass  → served from cache (fast, already verified)
	// - Visitors WITHOUT baskerville_pass → cache miss → PHP runs → challenge fires
	// This keeps caching working for verified users while new visitors always hit PHP.
	if (!empty($options['turnstile_under_attack'])) {
		// WP Rocket: vary cache by cookie presence/value
		add_filter('rocket_cache_dynamic_cookies', function( $cookies ) {
			$cookies[] = 'baskerville_pass';
			return $cookies;
		});
		// WP Rocket: also reject caching for requests WITHOUT the pass
		// (baskerville_pass absent = no cache file to serve = PHP runs)
		add_filter('rocket_cache_accept_cookies', function( $cookies ) {
			$cookies[] = 'baskerville_pass';
			return $cookies;
		});
		// W3 Total Cache: vary cache by cookie
		add_filter('w3tc_cache_key_cookies', function( $cookies ) {
			$cookies[] = 'baskerville_pass';
			return $cookies;
		});
		// LiteSpeed Cache: do not cache visitors without pass
		add_filter('litespeed_is_forced_nocache', function( $nocache ) {
			if (!isset($_COOKIE['baskerville_pass'])) {
				return true; // force no-cache for unchallenged visitors
			}
			return $nocache;
		});
		// SG Optimizer / SuperCacher
		add_filter('sgo_disable_cache', function( $disable ) {
			if (!isset($_COOKIE['baskerville_pass'])) {
				return true;
			}
			return $disable;
		});
		// Generic: DONOTCACHEPAGE for plugins that check it post-bootstrap
		// (WP Super Cache, W3TC, Comet Cache, etc.)
		// Does NOT help if advanced-cache.php already served the page.
		if (!isset($_COOKIE['baskerville_pass'])) {
			// phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals.NonPrefixedConstantFound -- WordPress-wide convention read by W3TC, WP Super Cache, Comet Cache, etc.
			if (!defined('DONOTCACHEPAGE')) define('DONOTCACHEPAGE', true);
		}
	}

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

	// Initialize Turnstile hooks (object already created before firewall)
	$turnstile->init();

	// Baskerville Cloud: LLM incident analysis + snapshots
	$cloud = new Baskerville_Cloud( $stats );
	add_action( 'baskerville_cloud_analyze',     [ $cloud, 'maybe_analyze' ] );
	add_action( 'baskerville_daily_rollup',      [ $cloud, 'run_daily_rollup' ] );
	add_action( 'baskerville_cleanup_snapshots', [ $cloud, 'cleanup_snapshots' ] );
	add_action( 'wp_dashboard_setup',            [ $cloud, 'register_dashboard_widget' ] );
	add_action( 'rest_api_init',                 [ $cloud, 'register_rest_routes' ] );

	// periodic statistics cleanup
	add_action('baskerville_cleanup_stats', [$stats, 'cleanup_old_stats']);

	// periodic cache file cleanup
	add_action('baskerville_cleanup_cache', [$core, 'fc_cleanup_old_files']);

	// periodic log file import to DB (file logging mode) - every minute for faster blocking
	add_action('baskerville_process_log_files', [$stats, 'process_log_files_to_db']);

	// periodic old log file cleanup
	add_action('baskerville_cleanup_log_files', [$stats, 'cleanup_old_log_files']);

	// periodic Deflect GeoIP database update (weekly)
	add_action('baskerville_update_deflect_geoip', function() {
		try {
			if (!class_exists('Baskerville_Deflect_GeoIP')) {
				$class_file = BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-deflect-geoip.php';
				if (!file_exists($class_file)) {
					return;
				}
				require_once $class_file;
			}
			$deflect = new Baskerville_Deflect_GeoIP();
			$deflect->update(true);
		} catch (\Exception $e) {
			/* translators: %s: error message */
			wp_trigger_error( '', sprintf( esc_html__( 'Baskerville: Deflect GeoIP update failed: %s', 'baskerville-ai-security' ), $e->getMessage() ), E_USER_WARNING );
		} catch (\Error $e) {
			/* translators: %s: error message */
			wp_trigger_error( '', sprintf( esc_html__( 'Baskerville: Deflect GeoIP update error: %s', 'baskerville-ai-security' ), $e->getMessage() ), E_USER_WARNING );
		}
	});

	// admin
	if (is_admin()) {
		new Baskerville_Admin($stats, $aiua);
	}
});

// activation/deactivation
register_activation_hook(__FILE__,   ['Baskerville_Installer', 'activate']);
register_deactivation_hook(__FILE__, ['Baskerville_Installer', 'deactivate']);
