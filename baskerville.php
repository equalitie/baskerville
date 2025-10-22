<?php
/**
 * Plugin Name:  Baskerville
 * Description:  A WordPress plugin by Equalitie.
 * Version:      1.0.0
 * Text Domain:  baskerville
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
require_once BASKERVILLE_PLUGIN_PATH . 'admin/class-baskerville-admin.php';

add_action('plugins_loaded', function () {
    // базовые сервисы
    $core  = new Baskerville_Core();
    $aiua  = new Baskerville_AI_UA($core);       // AI_UA должен принимать $core в конструкторе
    $stats = new Baskerville_Stats($core, $aiua); // Stats принимает Core и AI_UA

    // i18n + фронтовый JS + переключатель виджетов
    add_action('init', [$core, 'init']);                         // load_plugin_textdomain + add_fingerprinting_script
    add_action('init', [$core, 'handle_widget_toggle'], 0);      // раньше — чтобы выставить/снять cookie

    // ранняя установка идентификатора (до вывода)
    add_action('send_headers', [$core, 'ensure_baskerville_cookie'], 0);

    // pre-DB firewall (быстрее логгера страниц)
    $fw = new Baskerville_Firewall($core, $stats, $aiua);
    add_action('template_redirect', [$fw, 'pre_db_firewall'], -1);

    // логирование визитов публичных HTML-страниц
    add_action('template_redirect', [$stats, 'log_page_visit'], 0);

    // REST API
    $rest = new Baskerville_REST($core, $stats, $aiua);
    add_action('rest_api_init', [$rest, 'register_routes']);

    // периодическая очистка статистики
    add_action('baskerville_cleanup_stats', [$stats, 'cleanup_old_stats']);

    // админка
    if (is_admin()) {
        (new Baskerville_Admin())->register();
    }
});

// активация/деактивация
register_activation_hook(__FILE__,   ['Baskerville_Installer', 'activate']);
register_deactivation_hook(__FILE__, ['Baskerville_Installer', 'deactivate']);
