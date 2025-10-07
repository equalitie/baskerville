<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Admin {

    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
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

    public function admin_page() {
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>
            <form method="post" action="options.php">
                <?php
                settings_fields('baskerville_settings');
                do_settings_sections('baskerville_settings');
                submit_button();
                ?>
            </form>
        </div>
        <?php
    }
}