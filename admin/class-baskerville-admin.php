<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Admin {

    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
    }

    public function add_admin_menu() {
        add_options_page(
            __('Baskerville Settings', 'baskerville'),
            __('Baskerville', 'baskerville'),
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

        // General tab settings section
        add_settings_section(
            'baskerville_general_section',
            __('General Settings', 'baskerville'),
            null,
            'baskerville-general'
        );

        // Ban bots with 403 field
        add_settings_field(
            'ban_bots_403',
            __('Ban bots with 403 page', 'baskerville'),
            array($this, 'render_ban_bots_403_field'),
            'baskerville-general',
            'baskerville_general_section'
        );
    }

    public function sanitize_settings($input) {
        $sanitized = array();

        if (isset($input['ban_bots_403'])) {
            $sanitized['ban_bots_403'] = (bool) $input['ban_bots_403'];
        }

        return $sanitized;
    }

    public function render_ban_bots_403_field() {
        $options = get_option('baskerville_settings', array());
        $checked = isset($options['ban_bots_403']) && $options['ban_bots_403'];
        ?>
        <label>
            <input type="checkbox"
                   name="baskerville_settings[ban_bots_403]"
                   value="1"
                   <?php checked($checked, true); ?> />
            <?php _e('Enable 403 ban for detected bots', 'baskerville'); ?>
        </label>
        <?php
    }

    public function admin_page() {
        // Get current tab
        $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'general';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <!-- Tab Navigation -->
            <h2 class="nav-tab-wrapper">
                <a href="?page=baskerville-settings&tab=general"
                   class="nav-tab <?php echo $current_tab === 'general' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('General', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=traffic"
                   class="nav-tab <?php echo $current_tab === 'traffic' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Traffic', 'baskerville'); ?>
                </a>
            </h2>

            <!-- Tab Content -->
            <form method="post" action="options.php">
                <?php
                settings_fields('baskerville_settings_group');

                switch ($current_tab) {
                    case 'general':
                        do_settings_sections('baskerville-general');
                        submit_button();
                        break;

                    case 'traffic':
                        echo '<div class="notice notice-info"><p>' . __('Traffic settings will be available soon.', 'baskerville') . '</p></div>';
                        break;

                    default:
                        do_settings_sections('baskerville-general');
                        submit_button();
                        break;
                }
                ?>
            </form>
        </div>
        <?php
    }
}