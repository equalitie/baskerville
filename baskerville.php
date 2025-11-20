<?php
/**
 * Plugin Name:  Baskerville
 * Plugin URI: https://wordpress.org/plugins/baskerville/
 * Description:  A WordPress plugin by Equalitie.
 * Version:      1.0.0
 * Requires at least: 6.0
 * Requires PHP: 7.4
 * Author: eQalitie
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
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'includes/class-baskerville-maxmind-installer.php';
require_once BASKERVILLE_PLUGIN_PATH . 'admin/class-baskerville-admin.php';

// Add custom cron interval for file logging (5 minutes)
add_filter('cron_schedules', function($schedules) {
    $schedules['baskerville_5min'] = array(
        'interval' => 300, // 5 minutes in seconds
        'display'  => __('Every 5 Minutes (Baskerville)', 'baskerville')
    );
    return $schedules;
});

add_action('plugins_loaded', function () {
    // базовые сервисы
    $core  = new Baskerville_Core();
    $aiua  = new Baskerville_AI_UA($core);       // AI_UA должен принимать $core в конструкторе
    $stats = new Baskerville_Stats($core, $aiua); // Stats принимает Core и AI_UA

    // i18n + фронтовый JS + переключатель виджетов
    add_action('init', [$core, 'init']);                         // load_plugin_textdomain + add_fingerprinting_script
    add_action('init', [$core, 'handle_widget_toggle'], 0);      // раньше — чтобы выставить/снять cookie

    // pre-DB firewall (MUST run BEFORE any caching or template loading)
    $fw = new Baskerville_Firewall($core, $stats, $aiua);
    add_action('init', [$fw, 'pre_db_firewall'], -999999);

    // ранняя установка идентификатора (до вывода)
    add_action('send_headers', [$core, 'ensure_baskerville_cookie'], 0);

    // логирование визитов публичных HTML-страниц
    add_action('template_redirect', [$stats, 'log_page_visit'], 0);

    // REST API
    $rest = new Baskerville_REST($core, $stats, $aiua);
    add_action('rest_api_init', [$rest, 'register_routes']);

    // периодическая очистка статистики
    add_action('baskerville_cleanup_stats', [$stats, 'cleanup_old_stats']);

    // периодическая очистка кеш-файлов
    add_action('baskerville_cleanup_cache', [$core, 'fc_cleanup_old_files']);

    // периодический импорт логов из файлов в БД (file logging mode)
    add_action('baskerville_process_log_files', [$stats, 'process_log_files_to_db']);

    // периодическая очистка старых лог-файлов
    add_action('baskerville_cleanup_log_files', [$stats, 'cleanup_old_log_files']);

    // админка
    if (is_admin()) {
        new Baskerville_Admin();
    }
});

// активация/деактивация
register_activation_hook(__FILE__,   ['Baskerville_Installer', 'activate']);
register_deactivation_hook(__FILE__, ['Baskerville_Installer', 'deactivate']);
