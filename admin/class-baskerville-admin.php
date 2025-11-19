<?php

if (!defined('ABSPATH')) {
    exit;
}

class Baskerville_Admin {

    public function __construct() {
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'register_settings'));
        add_action('wp_ajax_baskerville_install_maxmind', array($this, 'ajax_install_maxmind'));
        add_action('wp_ajax_baskerville_clear_geoip_cache', array($this, 'ajax_clear_geoip_cache'));
        add_action('wp_ajax_baskerville_run_benchmark', array($this, 'ajax_run_benchmark'));
        add_action('admin_enqueue_scripts', array($this, 'enqueue_admin_scripts'));
    }

    public function enqueue_admin_scripts($hook) {
        // Only load on our settings page
        if ($hook !== 'settings_page_baskerville-settings') {
            return;
        }

        // Enqueue Select2 (bundled with WordPress)
        wp_enqueue_style('select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css', array(), '4.1.0');
        wp_enqueue_script('select2', 'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js', array('jquery'), '4.1.0', true);
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

        // Log page visits field (performance optimization)
        add_settings_field(
            'log_page_visits',
            __('Log page visits', 'baskerville'),
            array($this, 'render_log_page_visits_field'),
            'baskerville-general',
            'baskerville_general_section'
        );

        // Honeypot enabled field
        add_settings_field(
            'honeypot_enabled',
            __('AI Bot Honeypot', 'baskerville'),
            array($this, 'render_honeypot_enabled_field'),
            'baskerville-general',
            'baskerville_general_section'
        );

        // Honeypot ban enabled field
        add_settings_field(
            'honeypot_ban',
            __('Ban on Honeypot Trigger', 'baskerville'),
            array($this, 'render_honeypot_ban_field'),
            'baskerville-general',
            'baskerville_general_section'
        );

        // Countries tab settings section
        add_settings_section(
            'baskerville_countries_section',
            __('GeoIP Country Restrictions', 'baskerville'),
            null,
            'baskerville-countries'
        );

        // GeoIP mode field
        add_settings_field(
            'geoip_mode',
            __('GeoIP Access Mode', 'baskerville'),
            array($this, 'render_geoip_mode_field'),
            'baskerville-countries',
            'baskerville_countries_section'
        );

        // Blacklist countries field
        add_settings_field(
            'blacklist_countries',
            __('Black List Countries', 'baskerville'),
            array($this, 'render_blacklist_countries_field'),
            'baskerville-countries',
            'baskerville_countries_section'
        );

        // Whitelist countries field
        add_settings_field(
            'whitelist_countries',
            __('White List Countries', 'baskerville'),
            array($this, 'render_whitelist_countries_field'),
            'baskerville-countries',
            'baskerville_countries_section'
        );
    }

    public function sanitize_settings($input) {
        $sanitized = array();

        // Checkboxes: if not set in POST, they are unchecked (false)
        $sanitized['ban_bots_403'] = isset($input['ban_bots_403']) ? (bool) $input['ban_bots_403'] : false;

        if (isset($input['log_mode'])) {
            $mode = sanitize_text_field($input['log_mode']);
            $sanitized['log_mode'] = in_array($mode, array('disabled', 'file', 'database')) ? $mode : 'file';
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

        // Honeypot settings (checkboxes: false if not in POST)
        $sanitized['honeypot_enabled'] = isset($input['honeypot_enabled']) ? (bool) $input['honeypot_enabled'] : false;
        $sanitized['honeypot_ban'] = isset($input['honeypot_ban']) ? (bool) $input['honeypot_ban'] : false;

        // Flush rewrite rules when settings are saved (for honeypot route)
        flush_rewrite_rules();

        return $sanitized;
    }

    public function render_ban_bots_403_field() {
        $options = get_option('baskerville_settings', array());
        // Default to true if not set
        $checked = !isset($options['ban_bots_403']) || $options['ban_bots_403'];
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

    public function render_log_page_visits_field() {
        $options = get_option('baskerville_settings', array());
        // Default to 'file' for best balance (performance + analytics)
        $mode = isset($options['log_mode']) ? $options['log_mode'] : 'file';
        ?>
        <fieldset>
            <legend class="screen-reader-text"><span><?php _e('Page Visit Logging Mode', 'baskerville'); ?></span></legend>

            <label style="display: block; margin-bottom: 10px;">
                <input type="radio"
                       name="baskerville_settings[log_mode]"
                       value="disabled"
                       <?php checked($mode, 'disabled'); ?> />
                <strong><?php _e('Disabled', 'baskerville'); ?></strong> -
                <?php _e('No page visit logging (blocks & fingerprints still logged)', 'baskerville'); ?>
                <span style="color: #4CAF50;">⚡ ~0ms overhead</span>
            </label>

            <label style="display: block; margin-bottom: 10px;">
                <input type="radio"
                       name="baskerville_settings[log_mode]"
                       value="file"
                       <?php checked($mode, 'file'); ?> />
                <strong><?php _e('File Logging', 'baskerville'); ?></strong> -
                <?php _e('Write to log file, batch import to DB every minute', 'baskerville'); ?>
                <span style="color: #4CAF50;">⚡ ~1-2ms overhead</span>
                <strong style="color: #2196F3;">✓ Recommended</strong>
            </label>

            <label style="display: block; margin-bottom: 10px;">
                <input type="radio"
                       name="baskerville_settings[log_mode]"
                       value="database"
                       <?php checked($mode, 'database'); ?> />
                <strong><?php _e('Direct Database', 'baskerville'); ?></strong> -
                <?php _e('Write to database immediately (high overhead)', 'baskerville'); ?>
                <span style="color: #ff9800;">⚠️ ~500ms overhead on shared hosting</span>
            </label>

            <p class="description" style="margin-top: 15px; padding: 10px; background: #f0f0f1; border-left: 4px solid #2196F3;">
                <strong><?php _e('💡 Recommendation:', 'baskerville'); ?></strong><br>
                <?php _e('Use <strong>File Logging</strong> for best performance on shared hosting (GoDaddy, Bluehost, etc.)', 'baskerville'); ?><br>
                <?php _e('Full analytics with minimal overhead. Logs are processed in background every minute.', 'baskerville'); ?>
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
            <label style="display: block; margin-bottom: 10px;">
                <input type="radio"
                       name="baskerville_settings[geoip_mode]"
                       value="allow_all"
                       class="baskerville-geoip-mode-radio"
                       <?php checked($mode, 'allow_all'); ?> />
                <strong><?php _e('Allow All Countries', 'baskerville'); ?></strong> -
                <?php _e('No GeoIP restrictions (allow all countries)', 'baskerville'); ?>
            </label>
            <label style="display: block; margin-bottom: 10px;">
                <input type="radio"
                       name="baskerville_settings[geoip_mode]"
                       value="blacklist"
                       class="baskerville-geoip-mode-radio"
                       <?php checked($mode, 'blacklist'); ?> />
                <strong><?php _e('Black List', 'baskerville'); ?></strong> -
                <?php _e('Block access from specified countries', 'baskerville'); ?>
            </label>
            <label style="display: block;">
                <input type="radio"
                       name="baskerville_settings[geoip_mode]"
                       value="whitelist"
                       class="baskerville-geoip-mode-radio"
                       <?php checked($mode, 'whitelist'); ?> />
                <strong><?php _e('White List', 'baskerville'); ?></strong> -
                <?php _e('Allow access ONLY from specified countries', 'baskerville'); ?>
            </label>
        </fieldset>
        <p class="description">
            <?php _e('Choose whether to allow all countries, block specific countries, or allow only specific countries.', 'baskerville'); ?>
        </p>

        <script>
        jQuery(document).ready(function($) {
            // Initialize Select2 for country selects
            $('.baskerville-country-select').select2({
                placeholder: '<?php _e('Search and select countries...', 'baskerville'); ?>',
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
                    class="baskerville-country-select"
                    multiple="multiple"
                    style="width: 100%;">
                <?php foreach ($countries as $code => $name): ?>
                    <option value="<?php echo esc_attr($code); ?>"
                            <?php echo in_array($code, $selected_countries) ? 'selected' : ''; ?>>
                        <?php echo esc_html($name . ' (' . $code . ')'); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <p class="description">
                <strong style="color: #d32f2f;"><?php _e('Block access from these countries', 'baskerville'); ?></strong><br>
                <?php _e('Search and select countries to block. You can select multiple countries.', 'baskerville'); ?><br>
                <em style="color: #999;"><?php _e('This field is only active when "Black List" mode is selected above.', 'baskerville'); ?></em><br>
                <strong><?php _e('Current GeoIP source:', 'baskerville'); ?></strong> <?php echo esc_html($geoip_source); ?>
                <?php if ($geoip_source === 'MaxMind (if configured)'): ?>
                    <br><em><?php _e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville'); ?></em>
                    <br><em><?php _e('Download from: ', 'baskerville'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank">MaxMind GeoLite2</a></em>
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
                    class="baskerville-country-select"
                    multiple="multiple"
                    style="width: 100%;">
                <?php foreach ($countries as $code => $name): ?>
                    <option value="<?php echo esc_attr($code); ?>"
                            <?php echo in_array($code, $selected_countries) ? 'selected' : ''; ?>>
                        <?php echo esc_html($name . ' (' . $code . ')'); ?>
                    </option>
                <?php endforeach; ?>
            </select>
            <p class="description">
                <strong style="color: #2271b1;"><?php _e('Allow access ONLY from these countries', 'baskerville'); ?></strong><br>
                <?php _e('Search and select countries to allow. You can select multiple countries.', 'baskerville'); ?><br>
                <em style="color: #999;"><?php _e('This field is only active when "White List" mode is selected above.', 'baskerville'); ?></em><br>
                <strong><?php _e('Current GeoIP source:', 'baskerville'); ?></strong> <?php echo esc_html($geoip_source); ?>
                <?php if ($geoip_source === 'MaxMind (if configured)'): ?>
                    <br><em><?php _e('To use MaxMind GeoLite2, upload GeoLite2-Country.mmdb to /wp-content/uploads/geoip/', 'baskerville'); ?></em>
                    <br><em><?php _e('Download from: ', 'baskerville'); ?><a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank">MaxMind GeoLite2</a></em>
                <?php endif; ?>
            </p>
        </div>
        <?php
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

    private function get_countries_list() {
        return array(
            'AF' => 'Afghanistan',
            'AL' => 'Albania',
            'DZ' => 'Algeria',
            'AS' => 'American Samoa',
            'AD' => 'Andorra',
            'AO' => 'Angola',
            'AI' => 'Anguilla',
            'AQ' => 'Antarctica',
            'AG' => 'Antigua and Barbuda',
            'AR' => 'Argentina',
            'AM' => 'Armenia',
            'AW' => 'Aruba',
            'AU' => 'Australia',
            'AT' => 'Austria',
            'AZ' => 'Azerbaijan',
            'BS' => 'Bahamas',
            'BH' => 'Bahrain',
            'BD' => 'Bangladesh',
            'BB' => 'Barbados',
            'BY' => 'Belarus',
            'BE' => 'Belgium',
            'BZ' => 'Belize',
            'BJ' => 'Benin',
            'BM' => 'Bermuda',
            'BT' => 'Bhutan',
            'BO' => 'Bolivia',
            'BA' => 'Bosnia and Herzegovina',
            'BW' => 'Botswana',
            'BR' => 'Brazil',
            'BN' => 'Brunei',
            'BG' => 'Bulgaria',
            'BF' => 'Burkina Faso',
            'BI' => 'Burundi',
            'KH' => 'Cambodia',
            'CM' => 'Cameroon',
            'CA' => 'Canada',
            'CV' => 'Cape Verde',
            'KY' => 'Cayman Islands',
            'CF' => 'Central African Republic',
            'TD' => 'Chad',
            'CL' => 'Chile',
            'CN' => 'China',
            'CO' => 'Colombia',
            'KM' => 'Comoros',
            'CG' => 'Congo',
            'CD' => 'Congo (DRC)',
            'CK' => 'Cook Islands',
            'CR' => 'Costa Rica',
            'CI' => 'Côte d\'Ivoire',
            'HR' => 'Croatia',
            'CU' => 'Cuba',
            'CY' => 'Cyprus',
            'CZ' => 'Czech Republic',
            'DK' => 'Denmark',
            'DJ' => 'Djibouti',
            'DM' => 'Dominica',
            'DO' => 'Dominican Republic',
            'EC' => 'Ecuador',
            'EG' => 'Egypt',
            'SV' => 'El Salvador',
            'GQ' => 'Equatorial Guinea',
            'ER' => 'Eritrea',
            'EE' => 'Estonia',
            'ET' => 'Ethiopia',
            'FK' => 'Falkland Islands',
            'FO' => 'Faroe Islands',
            'FJ' => 'Fiji',
            'FI' => 'Finland',
            'FR' => 'France',
            'GF' => 'French Guiana',
            'PF' => 'French Polynesia',
            'GA' => 'Gabon',
            'GM' => 'Gambia',
            'GE' => 'Georgia',
            'DE' => 'Germany',
            'GH' => 'Ghana',
            'GI' => 'Gibraltar',
            'GR' => 'Greece',
            'GL' => 'Greenland',
            'GD' => 'Grenada',
            'GP' => 'Guadeloupe',
            'GU' => 'Guam',
            'GT' => 'Guatemala',
            'GN' => 'Guinea',
            'GW' => 'Guinea-Bissau',
            'GY' => 'Guyana',
            'HT' => 'Haiti',
            'HN' => 'Honduras',
            'HK' => 'Hong Kong',
            'HU' => 'Hungary',
            'IS' => 'Iceland',
            'IN' => 'India',
            'ID' => 'Indonesia',
            'IR' => 'Iran',
            'IQ' => 'Iraq',
            'IE' => 'Ireland',
            'IL' => 'Israel',
            'IT' => 'Italy',
            'JM' => 'Jamaica',
            'JP' => 'Japan',
            'JO' => 'Jordan',
            'KZ' => 'Kazakhstan',
            'KE' => 'Kenya',
            'KI' => 'Kiribati',
            'KP' => 'North Korea',
            'KR' => 'South Korea',
            'KW' => 'Kuwait',
            'KG' => 'Kyrgyzstan',
            'LA' => 'Laos',
            'LV' => 'Latvia',
            'LB' => 'Lebanon',
            'LS' => 'Lesotho',
            'LR' => 'Liberia',
            'LY' => 'Libya',
            'LI' => 'Liechtenstein',
            'LT' => 'Lithuania',
            'LU' => 'Luxembourg',
            'MO' => 'Macau',
            'MK' => 'North Macedonia',
            'MG' => 'Madagascar',
            'MW' => 'Malawi',
            'MY' => 'Malaysia',
            'MV' => 'Maldives',
            'ML' => 'Mali',
            'MT' => 'Malta',
            'MH' => 'Marshall Islands',
            'MQ' => 'Martinique',
            'MR' => 'Mauritania',
            'MU' => 'Mauritius',
            'YT' => 'Mayotte',
            'MX' => 'Mexico',
            'FM' => 'Micronesia',
            'MD' => 'Moldova',
            'MC' => 'Monaco',
            'MN' => 'Mongolia',
            'ME' => 'Montenegro',
            'MS' => 'Montserrat',
            'MA' => 'Morocco',
            'MZ' => 'Mozambique',
            'MM' => 'Myanmar',
            'NA' => 'Namibia',
            'NR' => 'Nauru',
            'NP' => 'Nepal',
            'NL' => 'Netherlands',
            'NC' => 'New Caledonia',
            'NZ' => 'New Zealand',
            'NI' => 'Nicaragua',
            'NE' => 'Niger',
            'NG' => 'Nigeria',
            'NU' => 'Niue',
            'NF' => 'Norfolk Island',
            'MP' => 'Northern Mariana Islands',
            'NO' => 'Norway',
            'OM' => 'Oman',
            'PK' => 'Pakistan',
            'PW' => 'Palau',
            'PS' => 'Palestine',
            'PA' => 'Panama',
            'PG' => 'Papua New Guinea',
            'PY' => 'Paraguay',
            'PE' => 'Peru',
            'PH' => 'Philippines',
            'PL' => 'Poland',
            'PT' => 'Portugal',
            'PR' => 'Puerto Rico',
            'QA' => 'Qatar',
            'RE' => 'Réunion',
            'RO' => 'Romania',
            'RU' => 'Russia',
            'RW' => 'Rwanda',
            'WS' => 'Samoa',
            'SM' => 'San Marino',
            'ST' => 'São Tomé and Príncipe',
            'SA' => 'Saudi Arabia',
            'SN' => 'Senegal',
            'RS' => 'Serbia',
            'SC' => 'Seychelles',
            'SL' => 'Sierra Leone',
            'SG' => 'Singapore',
            'SK' => 'Slovakia',
            'SI' => 'Slovenia',
            'SB' => 'Solomon Islands',
            'SO' => 'Somalia',
            'ZA' => 'South Africa',
            'SS' => 'South Sudan',
            'ES' => 'Spain',
            'LK' => 'Sri Lanka',
            'SD' => 'Sudan',
            'SR' => 'Suriname',
            'SZ' => 'Eswatini',
            'SE' => 'Sweden',
            'CH' => 'Switzerland',
            'SY' => 'Syria',
            'TW' => 'Taiwan',
            'TJ' => 'Tajikistan',
            'TZ' => 'Tanzania',
            'TH' => 'Thailand',
            'TL' => 'Timor-Leste',
            'TG' => 'Togo',
            'TK' => 'Tokelau',
            'TO' => 'Tonga',
            'TT' => 'Trinidad and Tobago',
            'TN' => 'Tunisia',
            'TR' => 'Turkey',
            'TM' => 'Turkmenistan',
            'TC' => 'Turks and Caicos Islands',
            'TV' => 'Tuvalu',
            'UG' => 'Uganda',
            'UA' => 'Ukraine',
            'AE' => 'United Arab Emirates',
            'GB' => 'United Kingdom',
            'US' => 'United States',
            'UY' => 'Uruguay',
            'UZ' => 'Uzbekistan',
            'VU' => 'Vanuatu',
            'VA' => 'Vatican City',
            'VE' => 'Venezuela',
            'VN' => 'Vietnam',
            'VG' => 'British Virgin Islands',
            'VI' => 'U.S. Virgin Islands',
            'WF' => 'Wallis and Futuna',
            'YE' => 'Yemen',
            'ZM' => 'Zambia',
            'ZW' => 'Zimbabwe'
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
            $title = __('White List Mode Active', 'baskerville');
            $description = sprintf(
                __('Access is allowed ONLY from %d %s: %s', 'baskerville'),
                $country_count,
                $country_count === 1 ? __('country', 'baskerville') : __('countries', 'baskerville'),
                '<strong>' . esc_html($countries_display) . '</strong>'
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
            $title = __('Black List Mode Active', 'baskerville');
            $description = sprintf(
                __('Access is blocked from %d %s: %s', 'baskerville'),
                $country_count,
                $country_count === 1 ? __('country', 'baskerville') : __('countries', 'baskerville'),
                '<strong>' . esc_html($countries_display) . '</strong>'
            );
        }
        ?>
        <div style="background: <?php echo esc_attr($banner_color); ?>; color: #fff; padding: 20px; border-radius: 4px; margin: 20px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.15); display: flex; align-items: center; gap: 15px;">
            <div style="font-size: 32px; font-weight: bold; opacity: 0.9;">
                <?php echo $icon; ?>
            </div>
            <div style="flex: 1;">
                <div style="font-size: 18px; font-weight: bold; margin-bottom: 5px;">
                    <?php echo esc_html($title); ?>
                </div>
                <div style="font-size: 14px; opacity: 0.95;">
                    <?php echo $description; ?>
                </div>
            </div>
        </div>
        <?php
    }

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

        $where_clause = $wpdb->prepare("WHERE timestamp_utc >= %s", $time_threshold);

        // Total visits
        $total_visits = (int) $wpdb->get_var("SELECT COUNT(*) FROM $table $where_clause");

        // Total unique IPs
        $total_ips = (int) $wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM $table $where_clause");

        // Blocked IPs (unique IPs that have block_reason)
        $blocked_ips = (int) $wpdb->get_var("SELECT COUNT(DISTINCT ip) FROM $table $where_clause AND block_reason IS NOT NULL AND block_reason != ''");

        // Calculate block rate
        $block_rate = $total_ips > 0 ? round(($blocked_ips / $total_ips) * 100, 2) : 0;

        return array(
            'total_visits' => $total_visits,
            'total_ips' => $total_ips,
            'blocked_ips' => $blocked_ips,
            'block_rate' => $block_rate,
            'hours' => $hours
        );
    }

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

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            FROM_UNIXTIME(
              FLOOR(UNIX_TIMESTAMP(CONVERT_TZ(timestamp_utc,'+00:00','+00:00'))/{$bucket_seconds})*{$bucket_seconds}
            ) AS time_slot,
            COUNT(*) AS total_visits,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score
          FROM $table_name
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
          GROUP BY time_slot
          ORDER BY time_slot ASC
        ";
        $results = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A);

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

    private function get_country_stats($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        // Get stats grouped by country_code directly from database
        $sql = $wpdb->prepare("
            SELECT
                COALESCE(NULLIF(country_code, ''), 'XX') as country_code,
                COUNT(*) as total_requests,
                SUM(CASE WHEN event_type = 'block' OR (block_reason IS NOT NULL AND block_reason != '') THEN 1 ELSE 0 END) as blocked_requests
            FROM {$table}
            WHERE timestamp_utc >= %s
            GROUP BY country_code
            ORDER BY total_requests DESC
        ", $cutoff);

        $results = $wpdb->get_results($sql, ARRAY_A);
        $all_countries = $this->get_countries_list();

        // Build country stats
        $country_stats = array();
        foreach ($results as $row) {
            $country_code = strtoupper($row['country_code']);

            if ($country_code === 'XX') {
                $country_name = 'Unknown';
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

    private function render_countries_tab() {
        // Get selected period from URL, default to 1day
        $period = isset($_GET['period']) ? sanitize_text_field($_GET['period']) : '1day';
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
        $base_url = admin_url('options-general.php?page=baskerville-settings&tab=countries');

        // Get country stats
        $country_stats = $this->get_country_stats($hours);

        // Get current GeoIP settings
        $options = get_option('baskerville_settings', array());
        $geoip_mode = isset($options['geoip_mode']) ? $options['geoip_mode'] : 'allow_all';
        $blacklist_countries = isset($options['blacklist_countries']) ? array_map('trim', explode(',', $options['blacklist_countries'])) : array();
        $whitelist_countries = isset($options['whitelist_countries']) ? array_map('trim', explode(',', $options['whitelist_countries'])) : array();

        ?>
        <style>
            .countries-stats-container {
                margin-top: 20px;
            }
            .countries-period-filters {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            .countries-period-btn {
                padding: 10px 20px;
                border: 2px solid #ddd;
                background: #fff;
                border-radius: 0;
                cursor: pointer;
                font-weight: 600;
                font-size: 14px;
                text-decoration: none;
                color: #555;
                transition: all 0.2s;
                display: inline-block;
            }
            .countries-period-btn:hover {
                border-color: #2271b1;
                color: #2271b1;
                text-decoration: none;
            }
            .countries-period-btn.active {
                background: linear-gradient(135deg, #2271b1 0%, #135e96 100%);
                color: #fff;
                border-color: #2271b1;
                box-shadow: 0 2px 4px rgba(34, 113, 177, 0.3);
            }
            .country-stats-table {
                background: #fff;
                padding: 20px;
                border: 1px solid #e0e0e0;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                margin-bottom: 30px;
            }
            .country-stats-table table {
                width: 100%;
                border-collapse: collapse;
            }
            .country-stats-table th {
                background: #f5f5f5;
                padding: 12px;
                text-align: left;
                font-weight: 600;
                border-bottom: 2px solid #ddd;
            }
            .country-stats-table td {
                padding: 10px 12px;
                border-bottom: 1px solid #eee;
            }
            .country-stats-table tr:hover {
                background: #f9f9f9;
            }
        </style>

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
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px;">
                    <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <canvas id="baskervilleCountryTrafficChart"></canvas>
                    </div>
                    <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <canvas id="baskervilleCountryBansChart"></canvas>
                    </div>
                </div>

                <!-- Country Stats Table -->
                <div class="country-stats-table">
                    <h3><?php _e('Traffic by Country', 'baskerville'); ?></h3>
                    <table>
                        <thead>
                            <tr>
                                <th><?php _e('Country', 'baskerville'); ?></th>
                                <th><?php _e('Total Requests', 'baskerville'); ?></th>
                                <th><?php _e('Blocked (403)', 'baskerville'); ?></th>
                                <th><?php _e('Block Rate', 'baskerville'); ?></th>
                                <th><?php _e('Access Status', 'baskerville'); ?></th>
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
                                        $status_label = __('Blocked (Blacklist)', 'baskerville');
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
                                        $status_label = __('Allowed (Whitelist)', 'baskerville');
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
                                <td style="color: <?php echo $stat['blocked'] > 0 ? '#d32f2f' : '#999'; ?>; font-weight: bold;">
                                    <?php echo number_format($stat['blocked']); ?>
                                </td>
                                <td>
                                    <span style="color: <?php echo $block_rate > 50 ? '#d32f2f' : ($block_rate > 20 ? '#ff9800' : '#4caf50'); ?>; font-weight: bold;">
                                        <?php echo $block_rate; ?>%
                                    </span>
                                </td>
                                <td>
                                    <span style="color: <?php echo esc_attr($status_color); ?>; font-weight: bold; font-size: 14px;">
                                        <?php echo $status_icon; ?> <?php echo esc_html($status_label); ?>
                                    </span>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                </div>
            <?php else: ?>
                <div style="background: #fff; padding: 40px; text-align: center; border: 1px solid #e0e0e0;">
                    <p><?php _e('No traffic data available for the selected period.', 'baskerville'); ?></p>
                </div>
            <?php endif; ?>
        </div>

        <?php if (!empty($country_stats)): ?>
        <!-- Chart.js Library -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

        <script>
        (function waitForChart() {
            if (typeof Chart === 'undefined') {
                setTimeout(waitForChart, 100);
                return;
            }

            const countryStats = <?php echo wp_json_encode($country_stats); ?>;
            const hours = <?php echo $hours; ?>;

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
                        label: 'Total Requests',
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
                            text: 'Traffic by Country — last ' + hours + 'h',
                            font: { size: 16, weight: 'bold' }
                        },
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            title: { display: true, text: 'Requests' }
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
                        label: '403 Blocked',
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
                            text: '403 Bans by Country — last ' + hours + 'h',
                            font: { size: 16, weight: 'bold' }
                        },
                        legend: { display: false }
                    },
                    scales: {
                        x: {
                            beginAtZero: true,
                            title: { display: true, text: 'Blocked Requests' }
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
        $period = isset($_GET['period']) ? sanitize_text_field($_GET['period']) : '1day';
        $valid_periods = array('12h', '1day', '3days', '7days');
        if (!in_array($period, $valid_periods)) {
            $period = '1day';
        }

        $stats = $this->get_traffic_stats($period);

        // Build URLs for period buttons
        $base_url = admin_url('options-general.php?page=baskerville-settings&tab=overview');
        ?>
        <style>
            .baskerville-traffic-stats {
                margin-top: 20px;
            }
            .baskerville-period-filters {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                flex-wrap: wrap;
            }
            .baskerville-period-btn {
                padding: 10px 20px;
                border: 2px solid #ddd;
                background: #fff;
                border-radius: 0;
                cursor: pointer;
                font-weight: 600;
                font-size: 14px;
                text-decoration: none;
                color: #555;
                transition: all 0.2s;
                display: inline-block;
            }
            .baskerville-period-btn:hover {
                border-color: #2271b1;
                color: #2271b1;
                text-decoration: none;
            }
            .baskerville-period-btn.active {
                background: linear-gradient(135deg, #2271b1 0%, #135e96 100%);
                color: #fff;
                border-color: #2271b1;
                box-shadow: 0 2px 4px rgba(34, 113, 177, 0.3);
            }
            .baskerville-stats-grid {
                display: grid;
                grid-template-columns: repeat(4, 1fr);
                gap: 20px;
                margin-bottom: 30px;
            }
            .baskerville-stat-card {
                background: #fff;
                border-radius: 0;
                padding: 30px 25px;
                text-align: center;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                transition: transform 0.2s, box-shadow 0.2s;
                border: 1px solid #e0e0e0;
            }
            .baskerville-stat-card:hover {
                transform: translateY(-3px);
                box-shadow: 0 6px 16px rgba(0, 0, 0, 0.15);
            }
            .baskerville-stat-card .stat-value {
                font-size: 36px;
                font-weight: 700;
                line-height: 1.2;
                margin-bottom: 10px;
            }
            .baskerville-stat-card .stat-label {
                font-size: 14px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                opacity: 0.7;
            }
            .stat-grey {
                background: linear-gradient(135deg, #718096 0%, #4a5568 100%);
                color: #fff;
                border: none;
            }
            .stat-dark-grey {
                background: linear-gradient(135deg, #4a5568 0%, #2d3748 100%);
                color: #fff;
                border: none;
            }
            .stat-red {
                background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                color: #fff;
                border: none;
            }
            @media (max-width: 1280px) {
                .baskerville-stats-grid {
                    grid-template-columns: repeat(2, 1fr);
                }
            }
            @media (max-width: 768px) {
                .baskerville-stats-grid {
                    grid-template-columns: 1fr;
                }
            }
        </style>
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
                    <div class="stat-label"><?php _e('Total Visits', 'baskerville'); ?></div>
                </div>
                <div class="baskerville-stat-card stat-dark-grey">
                    <div class="stat-value"><?php echo number_format($stats['total_ips']); ?></div>
                    <div class="stat-label"><?php _e('Total IPs', 'baskerville'); ?></div>
                </div>
                <div class="baskerville-stat-card stat-red">
                    <div class="stat-value"><?php echo number_format($stats['blocked_ips']); ?></div>
                    <div class="stat-label"><?php _e('IPs Blocked', 'baskerville'); ?></div>
                </div>
                <div class="baskerville-stat-card stat-red">
                    <div class="stat-value"><?php echo $stats['block_rate']; ?>%</div>
                    <div class="stat-label"><?php _e('Block Rate', 'baskerville'); ?></div>
                </div>
            </div>

            <!-- Charts Section -->
            <?php
            // Try to get timeseries data with error handling
            try {
                $timeseries = $this->get_timeseries_data($stats['hours']);
                ?>
                <div class="baskerville-charts-container" style="display: grid; grid-template-columns: 2fr 1fr; gap: 20px; margin-top: 20px;">
                    <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <canvas id="baskervilleHumAutoBar"></canvas>
                    </div>
                    <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1);">
                        <canvas id="baskervilleHumAutoPie"></canvas>
                    </div>
                </div>
            <?php
            } catch (Exception $e) {
                echo '<div class="notice notice-error"><p>Charts Error: ' . esc_html($e->getMessage()) . '</p></div>';
            }
            ?>
        </div>

        <?php if (isset($timeseries) && !empty($timeseries)): ?>
        <!-- Chart.js Library -->
        <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>

        <script>
        // Wait for Chart.js to load
        (function waitForChart() {
            if (typeof Chart === 'undefined') {
                setTimeout(waitForChart, 100);
                return;
            }

            const timeseries = <?php echo wp_json_encode($timeseries); ?>;
            const hours = <?php echo $stats['hours']; ?>;

            console.log('Timeseries data:', timeseries);
            console.log('Hours:', hours);

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
                            label: 'Humans',
                            data: humans,
                            stack: 'visits',
                            backgroundColor: '#4CAF50'
                        },
                        {
                            label: 'Automated',
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
                        x: { stacked: true, title: { display: true, text: 'Time' } },
                        y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Visits' } }
                    },
                    plugins: {
                        title: { display: true, text: 'Humans vs Automated — last ' + hours + 'h' },
                        tooltip: {
                            callbacks: {
                                afterBody(items) {
                                    const idx = items[0].dataIndex;
                                    const total = (humans[idx]||0) + (automated[idx]||0);
                                    const hp = total ? Math.round((humans[idx]*100)/total) : 0;
                                    const ap = total ? Math.round((automated[idx]*100)/total) : 0;
                                    return [`Total: ${total}`, `Humans: ${humans[idx]} (${hp}%)`, `Automated: ${automated[idx]} (${ap}%)`];
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
                    labels: ['Humans', 'Automated'],
                    datasets: [{
                        data: [totalHumans, totalAutomated],
                        backgroundColor: ['#4CAF50', '#FF9800']
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        title: { display: true, text: 'Traffic Distribution — last ' + hours + 'h' },
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
        })();
        </script>
        <?php endif; ?>
        <?php
    }

    public function ajax_install_maxmind() {
        check_ajax_referer('baskerville_install_maxmind', 'nonce');

        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => 'Insufficient permissions.'));
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
            wp_send_json_error(array('message' => 'Insufficient permissions.'));
        }

        $core = new Baskerville_Core();
        $cleared = $core->fc_clear_geoip_cache();

        wp_send_json_success(array(
            'message' => sprintf(__('Cleared %d GeoIP cache entries', 'baskerville'), $cleared),
            'cleared' => $cleared
        ));
    }

    private function render_geoip_test_tab() {
        // Always use current IP
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? '';
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
        <style>
            .geoip-test-container {
                margin-top: 20px;
            }
            .geoip-test-form {
                background: #fff;
                padding: 20px;
                border: 1px solid #e0e0e0;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            .geoip-results {
                background: #fff;
                padding: 20px;
                border: 1px solid #e0e0e0;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }
            .geoip-source {
                display: flex;
                align-items: center;
                padding: 15px;
                margin-bottom: 10px;
                border: 2px solid #e0e0e0;
                background: #f9f9f9;
                transition: all 0.2s;
            }
            .geoip-source:hover {
                border-color: #2271b1;
                transform: translateX(5px);
            }
            .geoip-source.available {
                border-color: #4CAF50;
                background: #f0f9f0;
            }
            .geoip-source.unavailable {
                border-color: #ddd;
                background: #f5f5f5;
                opacity: 0.7;
            }
            .geoip-source-name {
                font-weight: 600;
                width: 200px;
                color: #333;
            }
            .geoip-source-result {
                flex: 1;
                font-family: monospace;
                font-size: 14px;
            }
            .geoip-source-result.available {
                color: #2e7d32;
                font-weight: bold;
            }
            .geoip-source-result.unavailable {
                color: #999;
                font-style: italic;
            }
            .geoip-status-icon {
                width: 24px;
                height: 24px;
                margin-right: 10px;
                display: flex;
                align-items: center;
                justify-content: center;
                font-size: 18px;
            }
            .test-ip-input {
                width: 300px;
                padding: 8px 12px;
                font-size: 14px;
                border: 2px solid #ddd;
                margin-right: 10px;
            }
            .test-ip-button {
                padding: 8px 20px;
                background: #2271b1;
                color: #fff;
                border: none;
                cursor: pointer;
                font-size: 14px;
                font-weight: 600;
                transition: background 0.2s;
            }
            .test-ip-button:hover {
                background: #135e96;
            }
            .geoip-info-box {
                background: #e7f3ff;
                border-left: 4px solid #2271b1;
                padding: 15px;
                margin-bottom: 20px;
            }
        </style>

        <div class="geoip-test-container">
            <div class="geoip-test-form">
                <h2><?php _e('GeoIP Configuration Status', 'baskerville'); ?></h2>
                <p><?php _e('This page shows which GeoIP sources are configured and working for your server.', 'baskerville'); ?></p>
            </div>

            <?php if ($error): ?>
                <div style="background: #ffebee; border-left: 4px solid #d32f2f; padding: 20px; margin-top: 20px;">
                    <h3 style="color: #d32f2f; margin-top: 0;">❌ <?php _e('Error', 'baskerville'); ?></h3>
                    <p><strong><?php _e('Critical error occurred:', 'baskerville'); ?></strong></p>
                    <pre style="background: #fff; padding: 15px; border: 1px solid #ddd; overflow-x: auto; font-size: 12px;"><?php echo esc_html($error); ?></pre>
                    <p style="margin-bottom: 0;">
                        <small><?php _e('Please report this error to plugin support.', 'baskerville'); ?></small>
                    </p>
                </div>
            <?php elseif ($results): ?>
                <div class="geoip-info-box">
                    <strong><?php _e('Your IP:', 'baskerville'); ?></strong> <code><?php echo esc_html($current_ip); ?></code>
                    <br><strong><?php _e('Priority order:', 'baskerville'); ?></strong> NGINX GeoIP2 → NGINX GeoIP Legacy → NGINX Custom Header → Cloudflare → MaxMind
                </div>

                <div class="geoip-results">
                    <h2><?php _e('GeoIP Test Results', 'baskerville'); ?></h2>

                    <!-- NGINX GeoIP2 -->
                    <div class="geoip-source <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
                        <div class="geoip-status-icon"><?php echo $results['nginx_geoip2'] ? '✅' : '❌'; ?></div>
                        <div class="geoip-source-name">NGINX GeoIP2</div>
                        <div class="geoip-source-result <?php echo $results['nginx_geoip2'] ? 'available' : 'unavailable'; ?>">
                            <?php echo $results['nginx_geoip2'] ? esc_html($results['nginx_geoip2']) : __('Not configured', 'baskerville'); ?>
                        </div>
                    </div>

                    <!-- NGINX GeoIP Legacy -->
                    <div class="geoip-source <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
                        <div class="geoip-status-icon"><?php echo $results['nginx_geoip_legacy'] ? '✅' : '❌'; ?></div>
                        <div class="geoip-source-name">NGINX GeoIP (legacy)</div>
                        <div class="geoip-source-result <?php echo $results['nginx_geoip_legacy'] ? 'available' : 'unavailable'; ?>">
                            <?php echo $results['nginx_geoip_legacy'] ? esc_html($results['nginx_geoip_legacy']) : __('Not configured', 'baskerville'); ?>
                        </div>
                    </div>

                    <!-- NGINX Custom Header -->
                    <div class="geoip-source <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
                        <div class="geoip-status-icon"><?php echo $results['nginx_custom_header'] ? '✅' : '❌'; ?></div>
                        <div class="geoip-source-name">NGINX Custom Header</div>
                        <div class="geoip-source-result <?php echo $results['nginx_custom_header'] ? 'available' : 'unavailable'; ?>">
                            <?php echo $results['nginx_custom_header'] ? esc_html($results['nginx_custom_header']) : __('Not configured', 'baskerville'); ?>
                        </div>
                    </div>

                    <!-- Cloudflare -->
                    <div class="geoip-source <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
                        <div class="geoip-status-icon"><?php echo $results['cloudflare'] ? '✅' : '❌'; ?></div>
                        <div class="geoip-source-name">Cloudflare</div>
                        <div class="geoip-source-result <?php echo $results['cloudflare'] ? 'available' : 'unavailable'; ?>">
                            <?php echo $results['cloudflare'] ? esc_html($results['cloudflare']) : __('Not available', 'baskerville'); ?>
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
                                echo __('Database not found or not configured', 'baskerville');
                            }
                            ?>
                        </div>
                    </div>
                </div>

                <!-- MaxMind Debug Information -->
                <?php if (isset($results['maxmind_debug'])): ?>
                <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px;">
                    <h3><?php _e('MaxMind Debug Information', 'baskerville'); ?></h3>
                    <table style="width: 100%; border-collapse: collapse; font-family: monospace; font-size: 13px;">
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 8px; font-weight: bold; width: 200px;">Expected DB Path:</td>
                            <td style="padding: 8px; word-break: break-all;">
                                <code><?php echo esc_html($results['maxmind_debug']['expected_path']); ?></code>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd; background: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold;">File Exists:</td>
                            <td style="padding: 8px;">
                                <span style="color: <?php echo $results['maxmind_debug']['file_exists'] ? '#2e7d32' : '#d32f2f'; ?>; font-weight: bold;">
                                    <?php echo $results['maxmind_debug']['file_exists'] ? 'YES ✓' : 'NO ✗'; ?>
                                </span>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 8px; font-weight: bold;">File Readable:</td>
                            <td style="padding: 8px;">
                                <span style="color: <?php echo $results['maxmind_debug']['is_readable'] ? '#2e7d32' : '#d32f2f'; ?>; font-weight: bold;">
                                    <?php echo $results['maxmind_debug']['is_readable'] ? 'YES ✓' : 'NO ✗'; ?>
                                </span>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd; background: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold;">File Size:</td>
                            <td style="padding: 8px;">
                                <?php
                                if ($results['maxmind_debug']['file_size'] > 0) {
                                    echo number_format($results['maxmind_debug']['file_size'] / 1024 / 1024, 2) . ' MB';
                                } else {
                                    echo '<span style="color: #d32f2f;">0 bytes</span>';
                                }
                                ?>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 8px; font-weight: bold;">WP_CONTENT_DIR:</td>
                            <td style="padding: 8px;">
                                <code><?php echo esc_html($results['maxmind_debug']['wp_content_dir']); ?></code>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd; background: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold;">Autoload Path:</td>
                            <td style="padding: 8px; word-break: break-all;">
                                <code><?php echo esc_html($results['maxmind_debug']['autoload_path']); ?></code>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd;">
                            <td style="padding: 8px; font-weight: bold;">Autoload Exists:</td>
                            <td style="padding: 8px;">
                                <span style="color: <?php echo $results['maxmind_debug']['autoload_exists'] ? '#2e7d32' : '#d32f2f'; ?>; font-weight: bold;">
                                    <?php echo $results['maxmind_debug']['autoload_exists'] ? 'YES ✓' : 'NO ✗'; ?>
                                </span>
                            </td>
                        </tr>
                        <tr style="border-bottom: 1px solid #ddd; background: #f9f9f9;">
                            <td style="padding: 8px; font-weight: bold;">GeoIp2 Class Available:</td>
                            <td style="padding: 8px;">
                                <span style="color: <?php echo $results['maxmind_debug']['class_exists'] ? '#2e7d32' : '#d32f2f'; ?>; font-weight: bold;">
                                    <?php echo $results['maxmind_debug']['class_exists'] ? 'YES ✓' : 'NO ✗'; ?>
                                </span>
                            </td>
                        </tr>
                        <?php if (isset($results['maxmind_debug']['error'])): ?>
                        <tr style="border-bottom: 1px solid #ddd; background: #ffebee;">
                            <td style="padding: 8px; font-weight: bold;">Error Message:</td>
                            <td style="padding: 8px; color: #d32f2f;">
                                <?php echo esc_html($results['maxmind_debug']['error']); ?>
                            </td>
                        </tr>
                        <?php endif; ?>
                    </table>

                    <?php
                    // Provide specific help based on diagnostics
                    if (!$results['maxmind_debug']['file_exists']):
                    ?>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-top: 15px;">
                            <strong>⚠️ <?php _e('Database file not found!', 'baskerville'); ?></strong><br>
                            <?php _e('Please upload GeoLite2-Country.mmdb to:', 'baskerville'); ?><br>
                            <code style="display: block; margin: 10px 0; padding: 10px; background: #fff; border: 1px solid #ddd;">
                                <?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
                            </code>
                            <strong><?php _e('Download from:', 'baskerville'); ?></strong>
                            <a href="https://dev.maxmind.com/geoip/geolite2-free-geolocation-data" target="_blank">MaxMind GeoLite2</a>
                        </div>
                    <?php elseif (!$results['maxmind_debug']['is_readable']): ?>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-top: 15px;">
                            <strong>⚠️ <?php _e('Database file exists but is not readable!', 'baskerville'); ?></strong><br>
                            <?php _e('Check file permissions. Try:', 'baskerville'); ?><br>
                            <code style="display: block; margin: 10px 0; padding: 10px; background: #fff; border: 1px solid #ddd;">
                                chmod 644 <?php echo esc_html($results['maxmind_debug']['expected_path']); ?>
                            </code>
                        </div>
                    <?php elseif (!$results['maxmind_debug']['autoload_exists']): ?>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-top: 15px;">
                            <strong>⚠️ <?php _e('MaxMind PHP library not installed!', 'baskerville'); ?></strong><br>
                            <?php _e('Click the button below to install automatically (no Composer required):', 'baskerville'); ?><br>

                            <button id="baskerville-install-maxmind" class="button button-primary" style="margin-top: 15px;">
                                <?php _e('Install MaxMind Library', 'baskerville'); ?>
                            </button>
                            <span id="baskerville-install-status" style="margin-left: 10px;"></span>

                            <div style="margin-top: 15px; padding-top: 15px; border-top: 1px solid #ddd;">
                                <small><strong><?php _e('Or install manually with Composer:', 'baskerville'); ?></strong></small><br>
                                <code style="display: block; margin: 5px 0; padding: 10px; background: #fff; border: 1px solid #ddd; font-size: 11px;">
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

                                $btn.prop('disabled', true).text('<?php _e('Installing...', 'baskerville'); ?>');
                                $status.html('<span style="color: #666;">⏳ <?php _e('Downloading and installing library...', 'baskerville'); ?></span>');

                                $.ajax({
                                    url: ajaxurl,
                                    type: 'POST',
                                    data: {
                                        action: 'baskerville_install_maxmind',
                                        nonce: '<?php echo wp_create_nonce('baskerville_install_maxmind'); ?>'
                                    },
                                    success: function(response) {
                                        if (response.success) {
                                            $status.html('<span style="color: #2e7d32; font-weight: bold;">✓ ' + response.data.message + '</span>');
                                            setTimeout(function() {
                                                location.reload();
                                            }, 2000);
                                        } else {
                                            var errorMsg = response.data.message || 'Installation failed';
                                            var errorHtml = '<span style="color: #d32f2f;">✗ ' + errorMsg + '</span>';

                                            // Show detailed errors if available
                                            if (response.data.errors && response.data.errors.length > 0) {
                                                errorHtml += '<br><small style="color: #666;">Details: ' + response.data.errors.join(', ') + '</small>';
                                            }

                                            $status.html(errorHtml);
                                            $btn.prop('disabled', false).text('<?php _e('Retry Installation', 'baskerville'); ?>');
                                        }
                                    },
                                    error: function() {
                                        $status.html('<span style="color: #d32f2f;">✗ <?php _e('Installation failed. Please try again.', 'baskerville'); ?></span>');
                                        $btn.prop('disabled', false).text('<?php _e('Install MaxMind Library', 'baskerville'); ?>');
                                    }
                                });
                            });
                        });
                        </script>
                    <?php elseif ($results['maxmind_debug']['file_size'] == 0): ?>
                        <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin-top: 15px;">
                            <strong>⚠️ <?php _e('Database file is empty (0 bytes)!', 'baskerville'); ?></strong><br>
                            <?php _e('The file exists but has no data. Please re-download and upload the database.', 'baskerville'); ?>
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

                <div class="geoip-info-box" style="margin-top: 20px; background: #d4edda; border-left-color: #28a745;">
                    <strong><?php _e('Active Source:', 'baskerville'); ?></strong>
                    <?php echo $active_source ? esc_html($active_source) : __('None available', 'baskerville'); ?>
                    <?php if ($active_country): ?>
                        <br><strong><?php _e('Country Code:', 'baskerville'); ?></strong>
                        <span style="font-size: 16px; font-weight: bold; color: #155724;"><?php echo esc_html($active_country); ?></span>
                    <?php endif; ?>
                </div>

                <!-- Clear GeoIP Cache Button -->
                <div style="background: #fff; padding: 20px; border: 1px solid #e0e0e0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); margin-top: 20px;">
                    <h3><?php _e('GeoIP Cache Management', 'baskerville'); ?></h3>
                    <p><?php _e('If you are using a VPN or your IP location has changed, you may need to clear the GeoIP cache to see the updated country detection.', 'baskerville'); ?></p>
                    <p><?php _e('Cache TTL: 7 days', 'baskerville'); ?></p>

                    <button id="baskerville-clear-geoip-cache" class="button button-secondary" style="margin-top: 10px;">
                        🗑️ <?php _e('Clear GeoIP Cache', 'baskerville'); ?>
                    </button>
                    <span id="baskerville-clear-cache-status" style="margin-left: 10px;"></span>
                </div>

                <script>
                jQuery(document).ready(function($) {
                    $('#baskerville-clear-geoip-cache').on('click', function(e) {
                        e.preventDefault();
                        var $btn = $(this);
                        var $status = $('#baskerville-clear-cache-status');

                        $btn.prop('disabled', true).text('<?php _e('Clearing...', 'baskerville'); ?>');
                        $status.html('<span style="color: #666;">⏳ <?php _e('Clearing cache...', 'baskerville'); ?></span>');

                        $.ajax({
                            url: ajaxurl,
                            type: 'POST',
                            data: {
                                action: 'baskerville_clear_geoip_cache',
                                nonce: '<?php echo wp_create_nonce('baskerville_clear_geoip_cache'); ?>'
                            },
                            success: function(response) {
                                if (response.success) {
                                    $status.html('<span style="color: #2e7d32; font-weight: bold;">✓ ' + response.data.message + '</span>');
                                    $btn.text('🗑️ <?php _e('Clear GeoIP Cache', 'baskerville'); ?>');
                                    setTimeout(function() {
                                        location.reload();
                                    }, 1500);
                                } else {
                                    var errorMsg = response.data.message || 'Failed to clear cache';
                                    $status.html('<span style="color: #d32f2f;">✗ ' + errorMsg + '</span>');
                                    $btn.prop('disabled', false).text('🗑️ <?php _e('Clear GeoIP Cache', 'baskerville'); ?>');
                                }
                            },
                            error: function() {
                                $status.html('<span style="color: #d32f2f;">✗ <?php _e('Failed to clear cache. Please try again.', 'baskerville'); ?></span>');
                                $btn.prop('disabled', false).text('🗑️ <?php _e('Clear GeoIP Cache', 'baskerville'); ?>');
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
        // Get current tab
        $current_tab = isset($_GET['tab']) ? sanitize_text_field($_GET['tab']) : 'overview';
        ?>
        <div class="wrap">
            <h1><?php echo esc_html(get_admin_page_title()); ?></h1>

            <!-- Tab Navigation -->
            <h2 class="nav-tab-wrapper">
                <a href="?page=baskerville-settings&tab=overview"
                   class="nav-tab <?php echo $current_tab === 'overview' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Overview', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=countries"
                   class="nav-tab <?php echo $current_tab === 'countries' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Countries', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=settings"
                   class="nav-tab <?php echo $current_tab === 'settings' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Settings', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=ip-whitelist"
                   class="nav-tab <?php echo $current_tab === 'ip-whitelist' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('IP Whitelist', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=geoip-test"
                   class="nav-tab <?php echo $current_tab === 'geoip-test' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('GeoIP Test', 'baskerville'); ?>
                </a>
                <a href="?page=baskerville-settings&tab=performance"
                   class="nav-tab <?php echo $current_tab === 'performance' ? 'nav-tab-active' : ''; ?>">
                    <?php _e('Performance', 'baskerville'); ?>
                </a>
            </h2>

            <!-- Tab Content -->
            <form method="post" action="options.php">
                <?php
                settings_fields('baskerville_settings_group');

                switch ($current_tab) {
                    case 'overview':
                        ?>
                        </form>
                        <?php
                        $this->render_traffic_tab();
                        ?>
                        <form method="post" action="options.php">
                        <?php
                        break;

                    case 'countries':
                        // Display GeoIP settings form
                        settings_fields('baskerville_settings_group');
                        do_settings_sections('baskerville-countries');
                        submit_button();
                        ?>
                        </form>

                        <hr style="margin: 30px 0;">

                        <?php
                        // Display country statistics below the form
                        $this->render_countries_tab();
                        ?>
                        <form method="post" action="options.php">
                        <?php
                        break;

                    case 'settings':
                        do_settings_sections('baskerville-general');
                        submit_button();
                        break;

                    case 'ip-whitelist':
                        ?>
                        </form>
                        <?php
                        $this->render_ip_whitelist_tab();
                        ?>
                        <form method="post" action="options.php">
                        <?php
                        break;

                    case 'geoip-test':
                        ?>
                        </form>
                        <?php
                        $this->render_geoip_test_tab();
                        ?>
                        <form method="post" action="options.php">
                        <?php
                        break;

                    case 'performance':
                        ?>
                        </form>
                        <?php
                        $this->render_performance_tab();
                        ?>
                        <form method="post" action="options.php">
                        <?php
                        break;

                    default:
                        ?>
                        </form>
                        <?php
                        $this->render_traffic_tab();
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

    /* ===== IP Whitelist Tab ===== */
    private function render_ip_whitelist_tab() {
        $whitelist = get_option('baskerville_ip_whitelist', '');
        $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $ips_array = array_filter(preg_split('~[\s,]+~', $whitelist));

        // Handle form submission
        if (isset($_POST['baskerville_save_whitelist']) && check_admin_referer('baskerville_whitelist_save', 'baskerville_whitelist_nonce')) {
            $new_whitelist = sanitize_textarea_field($_POST['baskerville_ip_whitelist'] ?? '');
            update_option('baskerville_ip_whitelist', $new_whitelist);
            echo '<div class="notice notice-success"><p>' . __('IP Whitelist saved successfully!', 'baskerville') . '</p></div>';
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
                echo '<div class="notice notice-success"><p>' . sprintf(__('Added %s to whitelist!', 'baskerville'), esc_html($current_ip)) . '</p></div>';
                $whitelist = $new_whitelist;
                $ips_array = $current_ips;
            } else {
                echo '<div class="notice notice-info"><p>' . sprintf(__('%s is already in the whitelist.', 'baskerville'), esc_html($current_ip)) . '</p></div>';
            }
        }
        ?>
        <div class="baskerville-whitelist-tab">
            <h2><?php _e('IP Whitelist', 'baskerville'); ?></h2>

            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <p><?php _e('Whitelisted IP addresses bypass all firewall checks and will never be blocked by Baskerville.', 'baskerville'); ?></p>

                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 15px 0;">
                    <strong><?php _e('Your Current IP:', 'baskerville'); ?></strong>
                    <code style="background: #f5f5f5; padding: 4px 8px; border-radius: 3px; font-size: 14px;"><?php echo esc_html($current_ip); ?></code>

                    <?php if (!in_array($current_ip, $ips_array, true) && $current_ip !== 'unknown'): ?>
                        <form method="post" style="display: inline-block; margin-left: 10px;">
                            <?php wp_nonce_field('baskerville_whitelist_quick_add', 'baskerville_whitelist_quick_nonce'); ?>
                            <button type="submit" name="baskerville_quick_add_ip" class="button button-secondary" style="vertical-align: middle;">
                                ➕ <?php _e('Add My IP', 'baskerville'); ?>
                            </button>
                        </form>
                    <?php else: ?>
                        <span style="color: #46b450; margin-left: 10px;">✅ <?php _e('Already whitelisted', 'baskerville'); ?></span>
                    <?php endif; ?>
                </div>

                <form method="post">
                    <?php wp_nonce_field('baskerville_whitelist_save', 'baskerville_whitelist_nonce'); ?>

                    <table class="form-table">
                        <tr>
                            <th scope="row">
                                <label for="baskerville_ip_whitelist"><?php _e('Whitelisted IPs', 'baskerville'); ?></label>
                            </th>
                            <td>
                                <textarea
                                    name="baskerville_ip_whitelist"
                                    id="baskerville_ip_whitelist"
                                    rows="10"
                                    class="large-text code"
                                    style="font-family: monospace;"
                                ><?php echo esc_textarea($whitelist); ?></textarea>

                                <p class="description">
                                    <?php _e('Enter one IP address per line. You can also separate IPs with commas or spaces.', 'baskerville'); ?><br>
                                    <strong><?php _e('Supported formats:', 'baskerville'); ?></strong><br>
                                    • IPv4: <code>192.168.1.1</code><br>
                                    • IPv6: <code>2001:0db8:85a3::8a2e:0370:7334</code><br>
                                    • Multiple per line: <code>1.2.3.4, 5.6.7.8</code>
                                </p>
                            </td>
                        </tr>
                    </table>

                    <?php submit_button(__('Save Whitelist', 'baskerville'), 'primary', 'baskerville_save_whitelist'); ?>
                </form>
            </div>

            <?php if (!empty($ips_array)): ?>
            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <h3><?php _e('Currently Whitelisted IPs', 'baskerville'); ?> (<?php echo count($ips_array); ?>)</h3>
                <table class="widefat striped" style="margin-top: 10px;">
                    <thead>
                        <tr>
                            <th><?php _e('IP Address', 'baskerville'); ?></th>
                            <th><?php _e('Status', 'baskerville'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($ips_array as $ip): ?>
                        <tr>
                            <td>
                                <code style="font-size: 13px;"><?php echo esc_html($ip); ?></code>
                                <?php if ($ip === $current_ip): ?>
                                    <span style="color: #2271b1; font-weight: bold;"> (<?php _e('Your IP', 'baskerville'); ?>)</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)): ?>
                                    <span style="color: #46b450;">✓ <?php _e('Valid IPv4', 'baskerville'); ?></span>
                                <?php elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)): ?>
                                    <span style="color: #46b450;">✓ <?php _e('Valid IPv6', 'baskerville'); ?></span>
                                <?php else: ?>
                                    <span style="color: #d63638;">✗ <?php _e('Invalid IP', 'baskerville'); ?></span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php endif; ?>

            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <h3><?php _e('Use Cases', 'baskerville'); ?></h3>
                <ul style="line-height: 1.8;">
                    <li><strong><?php _e('Load Testing:', 'baskerville'); ?></strong> <?php _e('Add your server IP to run Apache Bench or similar tools', 'baskerville'); ?></li>
                    <li><strong><?php _e('Office Network:', 'baskerville'); ?></strong> <?php _e('Whitelist your company IP to ensure team members never get blocked', 'baskerville'); ?></li>
                    <li><strong><?php _e('Development:', 'baskerville'); ?></strong> <?php _e('Add localhost (127.0.0.1) if testing locally', 'baskerville'); ?></li>
                    <li><strong><?php _e('Monitoring Services:', 'baskerville'); ?></strong> <?php _e('Whitelist uptime monitors or site crawlers', 'baskerville'); ?></li>
                    <li><strong><?php _e('API Clients:', 'baskerville'); ?></strong> <?php _e('Add IPs of your API consumers', 'baskerville'); ?></li>
                </ul>

                <div style="background: #f0f6fc; border-left: 4px solid #0078d4; padding: 12px; margin-top: 15px;">
                    <strong>💡 <?php _e('Tip:', 'baskerville'); ?></strong>
                    <?php _e('Whitelisted IPs completely bypass the firewall. For better security, consider using GeoIP whitelist or verified crawler detection instead when possible.', 'baskerville'); ?>
                </div>
            </div>
        </div>
        <?php
    }

    /* ===== Performance Tab ===== */
    private function render_performance_tab() {
        ?>
        <div class="baskerville-performance-tab">
            <h2><?php _e('Performance Benchmarks', 'baskerville'); ?></h2>

            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <h3><?php _e('Internal Benchmarks', 'baskerville'); ?></h3>
                <p><?php _e('Run internal performance tests to measure the overhead of various Baskerville operations.', 'baskerville'); ?></p>

                <table class="widefat" style="margin-top: 15px;">
                    <thead>
                        <tr>
                            <th><?php _e('Test', 'baskerville'); ?></th>
                            <th><?php _e('Description', 'baskerville'); ?></th>
                            <th><?php _e('Action', 'baskerville'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong><?php _e('GeoIP Lookup', 'baskerville'); ?></strong></td>
                            <td><?php _e('Measure time to perform 100 GeoIP lookups', 'baskerville'); ?></td>
                            <td>
                                <button type="button" class="button benchmark-btn" data-test="geoip">
                                    <?php _e('Run Test', 'baskerville'); ?>
                                </button>
                                <span class="benchmark-result" data-test="geoip"></span>
                            </td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('AI/UA Classification', 'baskerville'); ?></strong></td>
                            <td><?php _e('Measure time to classify 100 user agents', 'baskerville'); ?></td>
                            <td>
                                <button type="button" class="button benchmark-btn" data-test="ai-ua">
                                    <?php _e('Run Test', 'baskerville'); ?>
                                </button>
                                <span class="benchmark-result" data-test="ai-ua"></span>
                            </td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Cache Operations', 'baskerville'); ?></strong></td>
                            <td><?php _e('Measure cache set/get performance (APCu: 1000 ops, File: 100 ops)', 'baskerville'); ?></td>
                            <td>
                                <button type="button" class="button benchmark-btn" data-test="cache">
                                    <?php _e('Run Test', 'baskerville'); ?>
                                </button>
                                <span class="benchmark-result" data-test="cache"></span>
                            </td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Full Firewall Check', 'baskerville'); ?></strong></td>
                            <td><?php _e('Simulate 100 complete firewall checks', 'baskerville'); ?></td>
                            <td>
                                <button type="button" class="button benchmark-btn" data-test="firewall">
                                    <?php _e('Run Test', 'baskerville'); ?>
                                </button>
                                <span class="benchmark-result" data-test="firewall"></span>
                            </td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Run All Tests', 'baskerville'); ?></strong></td>
                            <td><?php _e('Execute all benchmarks sequentially', 'baskerville'); ?></td>
                            <td>
                                <button type="button" class="button button-primary benchmark-btn" data-test="all">
                                    <?php _e('Run All', 'baskerville'); ?>
                                </button>
                                <span class="benchmark-result" data-test="all"></span>
                            </td>
                        </tr>
                    </tbody>
                </table>
            </div>

            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <h3><?php _e('External Load Testing', 'baskerville'); ?></h3>

                <h4><?php _e('Method 1: File Logging Mode (Recommended)', 'baskerville'); ?> ✅</h4>
                <p><?php _e('Test with firewall ACTIVE but using fast file logging:', 'baskerville'); ?></p>
                <ol style="line-height: 1.8;">
                    <li><?php _e('Go to Settings tab → Select "File Logging" mode', 'baskerville'); ?></li>
                    <li><?php _e('Run your tests - firewall will process requests normally', 'baskerville'); ?></li>
                    <li><?php _e('Deactivate plugin and test again to compare', 'baskerville'); ?></li>
                </ol>
                <p style="color: #2196F3;"><strong><?php _e('Expected overhead: ~50-70ms (5%)', 'baskerville'); ?></strong></p>

                <h4 style="margin-top: 20px;"><?php _e('Method 2: Whitelist Your IP', 'baskerville'); ?></h4>
                <p><?php _e('Test with firewall BYPASSED (shows minimum overhead):', 'baskerville'); ?></p>
                <p><?php _e('Go to IP Whitelist tab → Click "Add My IP" button → Run your tests', 'baskerville'); ?></p>

                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin: 15px 0;">
                    <strong><?php _e('Your Current IP:', 'baskerville'); ?></strong>
                    <code style="background: #f5f5f5; padding: 4px 8px; border-radius: 3px; font-size: 14px; margin-left: 5px;"><?php echo esc_html($_SERVER['REMOTE_ADDR'] ?? 'unknown'); ?></code>
                </div>
                <p style="color: #4CAF50;"><strong><?php _e('Expected overhead: ~0-5ms (0%)', 'baskerville'); ?></strong></p>

                <h4 style="margin-top: 20px;"><?php _e('Testing Commands', 'baskerville'); ?></h4>
                <pre style="background: #f5f5f5; padding: 10px; overflow-x: auto; margin-top: 10px;"># Test WITH plugin (10 samples with pauses)
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

                <h4 style="margin-top: 20px;"><?php _e('Expected Performance by Mode', 'baskerville'); ?></h4>
                <table class="widefat" style="margin-top: 10px;">
                    <thead>
                        <tr>
                            <th><?php _e('Logging Mode', 'baskerville'); ?></th>
                            <th><?php _e('Overhead', 'baskerville'); ?></th>
                            <th><?php _e('Analytics', 'baskerville'); ?></th>
                            <th><?php _e('Best For', 'baskerville'); ?></th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr>
                            <td><strong><?php _e('File Logging', 'baskerville'); ?></strong></td>
                            <td style="color: #4CAF50;">~50-70ms (5%)</td>
                            <td>✅ <?php _e('Full (5min delay)', 'baskerville'); ?></td>
                            <td><?php _e('Production', 'baskerville'); ?> ✅</td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Disabled', 'baskerville'); ?></strong></td>
                            <td style="color: #4CAF50;">~0ms (0%)</td>
                            <td>❌ <?php _e('None', 'baskerville'); ?></td>
                            <td><?php _e('Testing/Dev', 'baskerville'); ?></td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Database', 'baskerville'); ?></strong></td>
                            <td style="color: #ff9800;">~500ms (36%)</td>
                            <td>✅ <?php _e('Instant', 'baskerville'); ?></td>
                            <td><?php _e('VPS only', 'baskerville'); ?> ⚠️</td>
                        </tr>
                        <tr>
                            <td><strong><?php _e('Whitelisted IP', 'baskerville'); ?></strong></td>
                            <td style="color: #4CAF50;">~0-5ms (0%)</td>
                            <td>✅ <?php _e('Partial', 'baskerville'); ?></td>
                            <td><?php _e('Load testing', 'baskerville'); ?></td>
                        </tr>
                    </tbody>
                </table>

                <div style="background: #f0f6fc; border-left: 4px solid #0078d4; padding: 12px; margin-top: 15px;">
                    <strong>💡 <?php _e('Recommendation:', 'baskerville'); ?></strong>
                    <?php _e('Use <strong>File Logging</strong> mode (default) for production. It provides full analytics with minimal overhead (~5%), perfect for shared hosting.', 'baskerville'); ?>
                </div>

                <div style="background: #fff3cd; border-left: 4px solid #ffc107; padding: 12px; margin-top: 15px;">
                    <strong>⚠️ <?php _e('Note:', 'baskerville'); ?></strong>
                    <?php _e('Absolute response times vary by server, but overhead percentage is consistent. Focus on the % difference, not absolute milliseconds.', 'baskerville'); ?>
                </div>
            </div>

            <div class="card" style="max-width: 800px; margin: 20px 0;">
                <h3><?php _e('Performance Tips', 'baskerville'); ?></h3>
                <ul style="line-height: 1.8;">
                    <li><?php _e('Enable APCu for faster caching (file-based cache is slower)', 'baskerville'); ?></li>
                    <li><?php _e('Use NGINX GeoIP2 module for fastest country detection', 'baskerville'); ?></li>
                    <li><?php _e('Whitelist verified crawlers to reduce unnecessary checks', 'baskerville'); ?></li>
                    <li><?php _e('The firewall only runs on public HTML pages (not wp-admin, REST API, or AJAX)', 'baskerville'); ?></li>
                    <li><?php _e('Database writes are batched and use prepared statements', 'baskerville'); ?></li>
                </ul>
            </div>
        </div>

        <style>
            .baskerville-performance-tab .benchmark-result {
                margin-left: 10px;
                font-weight: bold;
            }
            .baskerville-performance-tab .benchmark-result.loading {
                color: #999;
            }
            .baskerville-performance-tab .benchmark-result.success {
                color: #46b450;
            }
            .baskerville-performance-tab .benchmark-result.error {
                color: #dc3232;
            }
            .baskerville-performance-tab pre {
                border-radius: 3px;
                font-size: 13px;
            }
        </style>

        <script type="text/javascript">
        jQuery(document).ready(function($) {
            $('.benchmark-btn').on('click', function() {
                var $btn = $(this);
                var test = $btn.data('test');
                var $result = $('.benchmark-result[data-test="' + test + '"]');

                $btn.prop('disabled', true);
                $result.removeClass('success error').addClass('loading').text('<?php _e('Running...', 'baskerville'); ?>');

                $.ajax({
                    url: ajaxurl,
                    type: 'POST',
                    data: {
                        action: 'baskerville_run_benchmark',
                        nonce: '<?php echo wp_create_nonce('baskerville_benchmark'); ?>',
                        test: test
                    },
                    success: function(response) {
                        if (response.success) {
                            $result.removeClass('loading').addClass('success').html(response.data.message);
                        } else {
                            $result.removeClass('loading').addClass('error').text(response.data.message || '<?php _e('Error', 'baskerville'); ?>');
                        }
                    },
                    error: function() {
                        $result.removeClass('loading').addClass('error').text('<?php _e('AJAX error', 'baskerville'); ?>');
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

    public function ajax_run_benchmark() {
        try {
            check_ajax_referer('baskerville_benchmark', 'nonce');

            if (!current_user_can('manage_options')) {
                wp_send_json_error(array('message' => 'Insufficient permissions.'));
                return;
            }

            $test = isset($_POST['test']) ? sanitize_text_field($_POST['test']) : '';

            if (empty($test)) {
                wp_send_json_error(array('message' => 'No test specified.'));
                return;
            }

            // Ensure classes are loaded
            if (!class_exists('Baskerville_Core')) {
                wp_send_json_error(array('message' => 'Baskerville_Core class not found.'));
                return;
            }

            $core = new Baskerville_Core();
            $aiua = null;

            // Only load AI_UA if needed
            if (in_array($test, array('ai-ua', 'firewall', 'all'), true)) {
                if (!class_exists('Baskerville_AI_UA')) {
                    wp_send_json_error(array('message' => 'Baskerville_AI_UA class not found.'));
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

                    $message = '<div style="text-align: left;">';
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
                    wp_send_json_error(array('message' => 'Invalid test type: ' . esc_html($test)));
                    return;
            }

            // Check if benchmark returned error
            if (isset($results['error']) && $results['error']) {
                wp_send_json_error($results);
                return;
            }

            wp_send_json_success($results);

        } catch (Exception $e) {
            error_log('Baskerville benchmark error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
            wp_send_json_error(array(
                'message' => 'Benchmark failed: ' . $e->getMessage(),
                'file' => basename($e->getFile()),
                'line' => $e->getLine()
            ));
        } catch (Error $e) {
            error_log('Baskerville benchmark fatal error: ' . $e->getMessage() . ' in ' . $e->getFile() . ':' . $e->getLine());
            wp_send_json_error(array(
                'message' => 'Fatal error: ' . $e->getMessage(),
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
        <label>
            <input type="checkbox"
                   name="baskerville_settings[honeypot_enabled]"
                   value="1"
                   <?php checked($enabled, true); ?> />
            <?php _e('Enable AI bot honeypot trap', 'baskerville'); ?>
        </label>
        <p class="description">
            <?php _e('Adds a hidden link to your site footer that is invisible to humans but visible to AI crawlers in HTML.', 'baskerville'); ?><br>
            <?php _e('When an IP accesses this link, it is immediately marked as an AI bot.', 'baskerville'); ?><br>
            <strong><?php _e('Honeypot URL:', 'baskerville'); ?></strong> <code><?php echo esc_html(home_url('/ai-training-data/')); ?></code><br>
            <em style="color: #d63638;"><?php _e('⚠️ The URL name "ai-training-data" is designed to attract AI bots looking for training content!', 'baskerville'); ?></em>
        </p>
        <?php
    }

    public function render_honeypot_ban_field() {
        $options = get_option('baskerville_settings', array());
        // Default to true if not set
        $ban_enabled = !isset($options['honeypot_ban']) || $options['honeypot_ban'];
        $honeypot_enabled = !isset($options['honeypot_enabled']) || $options['honeypot_enabled'];
        ?>
        <label>
            <input type="checkbox"
                   name="baskerville_settings[honeypot_ban]"
                   value="1"
                   <?php checked($ban_enabled, true); ?>
                   <?php disabled(!$honeypot_enabled); ?> />
            <?php _e('Ban IPs that trigger honeypot with 403', 'baskerville'); ?>
        </label>
        <p class="description">
            <?php _e('When enabled, IPs accessing the honeypot will be banned for 24 hours and receive a 403 Forbidden response.', 'baskerville'); ?><br>
            <?php _e('When disabled, the visit is still logged as AI bot, but the honeypot page is displayed normally.', 'baskerville'); ?>
        </p>
        <?php
    }
}