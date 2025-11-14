<?php

class Baskerville_Installer {

    /**
     * Вызывается при активации плагина.
     */
    public static function activate() {
        // Создаём вспомогательные объекты для работы со схемой БД
        $core  = new Baskerville_Core();
        $aiua  = new Baskerville_AI_UA($core);
        $stats = new Baskerville_Stats($core, $aiua);

        // Таблица статистики + апгрейд схемы
        // ВАЖНО: метод maybe_upgrade_schema должен быть public в Baskerville_Stats.
        $stats->create_stats_table();
        if (method_exists($stats, 'maybe_upgrade_schema')) {
            $stats->maybe_upgrade_schema();
        }

        // Опции по умолчанию (не перетираем, если уже есть)
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

        // Крон для регулярной очистки статистики
        if (!wp_next_scheduled('baskerville_cleanup_stats')) {
            wp_schedule_event(time(), 'daily', 'baskerville_cleanup_stats');
        }

        // Крон для очистки просроченных кеш-файлов
        if (!wp_next_scheduled('baskerville_cleanup_cache')) {
            wp_schedule_event(time(), 'daily', 'baskerville_cleanup_cache');
        }

        // Крон для импорта логов из файлов в БД (каждые 5 минут)
        if (!wp_next_scheduled('baskerville_process_log_files')) {
            wp_schedule_event(time(), 'baskerville_5min', 'baskerville_process_log_files');
        }

        // Крон для очистки старых лог-файлов (ежедневно)
        if (!wp_next_scheduled('baskerville_cleanup_log_files')) {
            wp_schedule_event(time(), 'daily', 'baskerville_cleanup_log_files');
        }

        // Перестройка правил (на случай, если есть свои эндпоинты/переписывание)
        flush_rewrite_rules();
    }

    /**
     * Вызывается при деактивации плагина.
     */
    public static function deactivate() {
        // Убираем крон-задачи
        wp_clear_scheduled_hook('baskerville_cleanup_stats');
        wp_clear_scheduled_hook('baskerville_cleanup_cache');
        wp_clear_scheduled_hook('baskerville_process_log_files');
        wp_clear_scheduled_hook('baskerville_cleanup_log_files');

        // Чистим правила
        flush_rewrite_rules();
    }
}
