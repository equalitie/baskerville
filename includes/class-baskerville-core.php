<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Core {

    public function __construct() {
        $this->init_hooks();
    }

    private function init_hooks() {
        add_action('wp_enqueue_scripts', array($this, 'enqueue_scripts'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }

    public function enqueue_scripts() {
        wp_enqueue_style(
            'baskerville-style',
            BASKERVILLE_PLUGIN_URL . 'assets/css/baskerville.css',
            array(),
            BASKERVILLE_VERSION
        );

        wp_enqueue_script(
            'baskerville-script',
            BASKERVILLE_PLUGIN_URL . 'assets/js/baskerville.js',
            array('jquery'),
            BASKERVILLE_VERSION,
            true
        );
    }

    public function enqueue_admin_scripts() {
        wp_enqueue_style(
            'baskerville-admin-style',
            BASKERVILLE_PLUGIN_URL . 'assets/css/admin.css',
            array(),
            BASKERVILLE_VERSION
        );

        wp_enqueue_script(
            'baskerville-admin-script',
            BASKERVILLE_PLUGIN_URL . 'assets/js/admin.js',
            array('jquery'),
            BASKERVILLE_VERSION,
            true
        );
    }
}