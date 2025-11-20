<?php

class Baskerville_Stats
{
    /** @var Baskerville_Core */
    private $core;

    /** @var Baskerville_AI_UA */
    private $aiua;

    /** Current visit_key of the last page/fp record within the request (if needed externally) */
    public $current_visit_key = null;

    public function __construct(Baskerville_Core $core, Baskerville_AI_UA $aiua) {
        $this->core = $core;
        $this->aiua = $aiua;
    }

    public function create_stats_table() {
        global $wpdb;

        $table_name = $wpdb->prefix . 'baskerville_stats';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
          id bigint(20) NOT NULL AUTO_INCREMENT,
          visit_key varchar(255) NOT NULL,
          ip varchar(45) NOT NULL,
          country_code varchar(2) NULL,
          baskerville_id varchar(100) NOT NULL,
          fingerprint_hash varchar(64) NULL,
          timestamp_utc datetime NOT NULL,
          score int(3) NOT NULL DEFAULT 0,
          classification varchar(50) NOT NULL DEFAULT 'unknown',
          user_agent text NOT NULL,
          evaluation_json longtext NOT NULL,
          score_reasons text NOT NULL,
          classification_reason text NOT NULL,
          block_reason varchar(128) NULL,
          event_type varchar(16) NOT NULL DEFAULT 'fp',

          had_fp tinyint(1) NOT NULL DEFAULT 0,
          fp_received_at datetime NULL,
          visit_count int(11) NOT NULL DEFAULT 1,

          top_factor_json longtext NULL,
          top_factor varchar(64) NULL,

          created_at timestamp DEFAULT CURRENT_TIMESTAMP,
          updated_at timestamp DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          PRIMARY KEY (id),
          UNIQUE KEY visit_key (visit_key),
          KEY ip (ip),
          KEY country_code (country_code),
          KEY baskerville_id (baskerville_id),
          KEY timestamp_utc (timestamp_utc),
          KEY classification (classification),
          KEY score (score),
          KEY event_type (event_type),
          KEY fingerprint_hash (fingerprint_hash),
          KEY block_reason (block_reason),
          KEY top_factor (top_factor)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);

        add_option('baskerville_db_version', '1.0');
    }

    public function maybe_upgrade_schema() {
        global $wpdb;
        $t = $wpdb->prefix . 'baskerville_stats';

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'had_fp'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN had_fp TINYINT(1) NOT NULL DEFAULT 0"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'fp_received_at'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN fp_received_at DATETIME NULL"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'visit_count'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN visit_count INT(11) NOT NULL DEFAULT 1"); }

        $idx_any    = $wpdb->get_var("SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{$t}' AND index_name='visit_key' LIMIT 1");
        $idx_unique = $wpdb->get_var("SELECT 1 FROM information_schema.statistics WHERE table_schema=DATABASE() AND table_name='{$t}' AND index_name='visit_key' AND non_unique=0 LIMIT 1");
        if ($idx_any && !$idx_unique) { $wpdb->query("DROP INDEX visit_key ON $t"); }
        if (!$idx_unique) { $wpdb->query("ALTER TABLE $t ADD UNIQUE KEY visit_key (visit_key)"); }

        $idx = $wpdb->get_results("SHOW INDEX FROM $t WHERE Key_name='idx_burst'");
        if (!$idx) {
            $wpdb->query("CREATE INDEX idx_burst ON $t (ip, event_type, had_fp, timestamp_utc)");
        }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'fingerprint_hash'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN fingerprint_hash VARCHAR(64) NULL");
            $wpdb->query("CREATE INDEX fingerprint_hash ON $t (fingerprint_hash)");
        }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'block_reason'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN block_reason VARCHAR(128) NULL AFTER classification_reason");
            $wpdb->query("CREATE INDEX block_reason ON $t (block_reason)");
        }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'top_factor_json'");
        if (!$col) { $wpdb->query("ALTER TABLE $t ADD COLUMN top_factor_json LONGTEXT NULL"); }

        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'top_factor'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN top_factor VARCHAR(64) NULL AFTER top_factor_json");
            $wpdb->query("CREATE INDEX top_factor ON $t (top_factor)");
        }

        // Add country_code field for GeoIP
        $col = $wpdb->get_results("SHOW COLUMNS FROM $t LIKE 'country_code'");
        if (!$col) {
            $wpdb->query("ALTER TABLE $t ADD COLUMN country_code VARCHAR(2) NULL AFTER ip");
            $wpdb->query("CREATE INDEX country_code ON $t (country_code)");
        }
    }

    public function get_retention_days() {
        return (int) get_option('baskerville_retention_days', BASKERVILLE_DEFAULT_RETENTION_DAYS);
    }

    public function cleanup_old_stats($force = false) {
        global $wpdb;

        $table_name = $wpdb->prefix . 'baskerville_stats';
        $retention_days = $this->get_retention_days();

        if ($retention_days < 1 && !$force) {
            error_log('Baskerville: Cleanup skipped - retention period too short');
            return false;
        }

        $result = $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM $table_name WHERE timestamp_utc < DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d DAY)",
                $retention_days
            )
        );

        if ($result === false) {
            error_log('Baskerville: Cleanup failed - ' . $wpdb->last_error);
            return false;
        }

        if ($result > 0) {
            error_log("Baskerville: Cleaned up $result old statistics records (older than $retention_days days)");
        }

        return $result;
    }

    public function maybe_cleanup_stats() {
        if (wp_rand(1, 100) <= 5) { // 5%
            $this->cleanup_old_stats();
        }
    }

    public function make_visit_key(string $ip, ?string $bid): string {
        return hash('sha256', $ip . '|' . $bid . '|' . microtime(true) . '|' . bin2hex(random_bytes(8)));
    }

    /** Returns [json_string|null, top_name|null] from $evaluation['top_factors'] or fp-cookie. */
    public function extract_top_factors(array $evaluation, ?array $fp_cookie = null): array {
        $top = $evaluation['top_factors'] ?? $evaluation['contrib'] ?? null;

        if ((!is_array($top) || !$top) && is_array($fp_cookie) && !empty($fp_cookie['top'])) {
            $top = $fp_cookie['top'];
        }

        if (!is_array($top) || !$top) return [null, null];

        $norm = [];
        foreach (array_slice($top, 0, 6) as $x) {
            $norm[] = [
                'key'   => (string)($x['key']   ?? ''),
                'delta' => (int)   ($x['delta'] ?? 0),
                'why'   => (string)($x['why']   ?? '')
            ];
        }

        $main = null; $best = -1;
        foreach ($norm as $x) {
            $w = abs((int)$x['delta']);
            if ($w > $best) { $best = $w; $main = (string)$x['key']; }
        }
        if (!$main && !empty($norm[0]['key'])) $main = (string)$norm[0]['key'];
        if ($main !== null) { $main = mb_substr($main, 0, 64); }

        return [wp_json_encode($norm, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), $main];
    }

    public function save_visit_stats($ip, $baskerville_id, $evaluation, $classification, $user_agent, $event_type = 'fp', $visit_key = null, $block_reason = null) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        $visit_key = $visit_key ?: $this->make_visit_key($ip, $baskerville_id);

        $fp_cookie = $this->core->read_fp_cookie();
        [$top_json, $top_name] = $this->extract_top_factors((array)$evaluation, $fp_cookie);

        // Get country code for GeoIP analytics
        $country_code = $this->core->get_country_by_ip($ip);

        $data = [
            'visit_key'             => $visit_key,
            'ip'                    => $ip,
            'country_code'          => $country_code,
            'baskerville_id'        => $baskerville_id,
            'timestamp_utc'         => current_time('mysql', true),
            'score'                 => (int)($evaluation['score'] ?? 0),
            'classification'        => (string)($classification['classification'] ?? 'unknown'),
            'user_agent'            => $user_agent,
            'evaluation_json'       => wp_json_encode($evaluation),
            'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
            'classification_reason' => (string)($classification['reason'] ?? ''),
            'block_reason'          => $block_reason,
            'event_type'            => $event_type,
            'top_factor_json'       => $top_json,
            'top_factor'            => $top_name,
        ];
        $fmt = ['%s','%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%s','%s','%s','%s'];

        $ok = $wpdb->insert($table_name, $data, $fmt);
        if ($ok === false) {
            error_log('Baskerville: insert failed - ' . $wpdb->last_error);
            return false;
        }
        return $visit_key;
    }

    public function update_visit_stats_by_key(string $visit_key, array $evaluation, array $classification, ?string $fp_hash = null): bool {
        global $wpdb;
        $t = $wpdb->prefix . 'baskerville_stats';

        $fp_cookie = $this->core->read_fp_cookie();
        [$top_json, $top_name] = $this->extract_top_factors($evaluation, $fp_cookie);

        $data = [
            'score'                 => (int)($evaluation['score'] ?? 0),
            'classification'        => (string)($classification['classification'] ?? 'unknown'),
            'evaluation_json'       => wp_json_encode($evaluation),
            'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
            'classification_reason' => (string)($classification['reason'] ?? ''),
            'had_fp'                => 1,
            'fp_received_at'        => current_time('mysql', true),
        ];
        $fmt = ['%d','%s','%s','%s','%s','%d','%s'];

        if ($fp_hash)  { $data['fingerprint_hash'] = $fp_hash;  $fmt[] = '%s'; }
        if ($top_json) { $data['top_factor_json']  = $top_json; $fmt[] = '%s'; }
        if ($top_name) { $data['top_factor']       = $top_name; $fmt[] = '%s'; }

        $ok = $wpdb->update($t, $data, ['visit_key' => $visit_key], $fmt, ['%s']);
        if ($ok === false) {
            error_log('Baskerville: update by visit_key failed - ' . $wpdb->last_error);
            return false;
        }
        return $ok > 0;
    }

    public function log_page_visit() {
        // Only public HTML pages — without duplicating logic
        if (!$this->core->is_public_html_request()) return;

        $ip = $_SERVER['REMOTE_ADDR'] ?? '';

        // Skip logging for whitelisted IPs (performance optimization)
        if ($this->core->is_whitelisted_ip($ip)) return;

        // Check logging mode (disabled/file/database)
        $options = get_option('baskerville_settings', array());
        $log_mode = isset($options['log_mode']) ? $options['log_mode'] : 'file'; // Default to 'file'

        if ($log_mode === 'disabled') {
            return; // No logging at all
        }

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';

        $headers = [
            'accept'           => $_SERVER['HTTP_ACCEPT'] ?? null,
            'accept_language'  => $_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? null,
            'user_agent'       => $ua,
            'sec_ch_ua'        => $_SERVER['HTTP_SEC_CH_UA'] ?? null,
        ];

        // Classify by server headers (without JS)
        $evaluation = $this->aiua->baskerville_score_fp(['fingerprint' => []], ['headers' => $headers]);

        // If fp-cookie already exists — score can be adjusted/pulled
        $fp_cookie = $this->core->read_fp_cookie();
        if ($fp_cookie && isset($fp_cookie['score'])) {
            $evaluation['score'] = (int)$fp_cookie['score'];
        }

        $classification = $this->aiua->classify_client(['fingerprint' => []], ['headers' => $headers]);

        $cookie_id = $this->core->get_cookie_id();
        $visit_key = $this->make_visit_key($ip, $cookie_id);
        $this->current_visit_key = $visit_key;

        // short-lived cookie for linking with fetch/beacon
        setcookie('baskerville_visit_key', $visit_key, [
            'expires'  => time() + 300,
            'path'     => '/',
            'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
            'httponly' => false,
            'samesite' => 'Lax',
        ]);

        // Log according to selected mode
        if ($log_mode === 'file') {
            // Fast file logging (~1-2ms)
            $this->log_page_visit_to_file($ip, $cookie_id ?? '', $evaluation, $classification, $ua, $visit_key);
        } else {
            // Direct database logging (~500ms on shared hosting)
            $this->save_visit_stats($ip, $cookie_id ?? '', $evaluation, $classification, $ua, 'page', $visit_key);
        }
    }

    public function get_timeseries_data($hours = 24) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            FROM_UNIXTIME(
              FLOOR(UNIX_TIMESTAMP(CONVERT_TZ(timestamp_utc,'+00:00','+00:00'))/900)*900
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
            $human    = (int)$r['human_count'];
            $bad      = (int)$r['bad_bot_count'];
            $ai       = (int)$r['ai_bot_count'];
            $bot      = (int)$r['bot_count'];
            $verified = (int)$r['verified_bot_count'];
            $botsum   = $bad + $ai + $bot + $verified;

            $out[] = [
                'time'                => $r['time_slot'],
                'total_visits'        => $total,
                'human_count'         => $human,
                'bad_bot_count'       => $bad,
                'ai_bot_count'        => $ai,
                'bot_count'           => $bot,
                'verified_bot_count'  => $verified,
                'bot_percentage'      => $total ? round($botsum * 100 / $total, 1) : 0,
                'avg_score'           => round((float)$r['avg_score'], 1),
            ];
        }
        return $out;
    }

    public function get_summary_stats_window($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) AS total_visits,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score
          FROM $table
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $total = (int)($row['total_visits'] ?? 0);
        $bots  = (int)($row['bad_bot_count'] ?? 0)
               + (int)($row['ai_bot_count']  ?? 0)
               + (int)($row['bot_count']     ?? 0)
               + (int)($row['verified_bot_count'] ?? 0);
        $hum   = (int)($row['human_count'] ?? 0);

        return [
            'total_visits'     => $total,
            'human_count'      => $hum,
            'human_percentage' => $total ? round($hum * 100 / $total, 1) : 0,
            'bad_bot_count'    => (int)($row['bad_bot_count'] ?? 0),
            'ai_bot_count'     => (int)($row['ai_bot_count'] ?? 0),
            'bot_count'        => (int)($row['bot_count'] ?? 0),
            'bot_total'        => $bots,
            'bot_percentage'   => $total ? round($bots * 100 / $total, 1) : 0,
            'avg_score'        => round((float)($row['avg_score'] ?? 0), 1),
            'hours'            => $hours,
        ];
    }

    public function get_summary_stats() {
        global $wpdb;
        $table  = $wpdb->prefix . 'baskerville_stats';
        $days   = (int)$this->get_retention_days();
        $cutoff = gmdate('Y-m-d H:i:s', time() - $days * 86400);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) total_visits,
            COUNT(DISTINCT ip) unique_ips,
            SUM(CASE WHEN classification='human'   THEN 1 ELSE 0 END) human_count,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) bad_bot_count,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) ai_bot_count,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) bot_count,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_count,
            AVG(CASE WHEN had_fp=1 THEN score END) AS avg_score,
            MIN(timestamp_utc) first_record,
            MAX(timestamp_utc) last_record
          FROM $table
          WHERE event_type IN ('page','fp') AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A);
        if (!$row) return [];

        $total = (int)$row['total_visits'];
        $bots  = (int)($row['bad_bot_count'] ?? 0)
               + (int)($row['ai_bot_count']  ?? 0)
               + (int)($row['bot_count']     ?? 0)
               + (int)($row['verified_bot_count'] ?? 0);

        return [
            'total_visits'     => $total,
            'unique_ips'       => (int)$row['unique_ips'],
            'human_count'      => (int)$row['human_count'],
            'human_percentage' => $total ? round($row['human_count'] * 100 / $total, 1) : 0,
            'bad_bot_count'    => (int)$row['bad_bot_count'],
            'ai_bot_count'     => (int)$row['ai_bot_count'],
            'bot_count'        => (int)$row['bot_count'],
            'bot_total'        => $bots,
            'bot_percentage'   => $total ? round($bots * 100 / $total, 1) : 0,
            'avg_score'        => round((float)$row['avg_score'], 1),
            'retention_days'   => $days,
            'first_record'     => $row['first_record'],
            'last_record'      => $row['last_record'],
        ];
    }

    public function get_block_timeseries_data($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            FROM_UNIXTIME(
              FLOOR(UNIX_TIMESTAMP(CONVERT_TZ(timestamp_utc,'+00:00','+00:00'))/900)*900
            ) AS time_slot,
            COUNT(*) AS total_blocks,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_blocks,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_blocks,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_blocks,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_blocks,
            SUM(CASE WHEN classification NOT IN ('bad_bot','ai_bot','bot') THEN 1 ELSE 0 END) AS other_blocks
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
          GROUP BY time_slot
          ORDER BY time_slot ASC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $out = [];
        foreach ($rows as $r) {
            $out[] = [
                'time'                 => $r['time_slot'],
                'total_blocks'         => (int)$r['total_blocks'],
                'bad_bot_blocks'       => (int)$r['bad_bot_blocks'],
                'verified_bot_blocks'  => (int)$r['verified_bot_blocks'],
                'ai_bot_blocks'        => (int)$r['ai_bot_blocks'],
                'bot_blocks'           => (int)$r['bot_blocks'],
                'other_blocks'         => (int)$r['other_blocks'],
            ];
        }
        return $out;
    }

    public function get_block_summary($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            COUNT(*) AS total_blocks,
            SUM(CASE WHEN classification='bad_bot' THEN 1 ELSE 0 END) AS bad_bot_blocks,
            SUM(CASE WHEN classification='ai_bot'  THEN 1 ELSE 0 END) AS ai_bot_blocks,
            SUM(CASE WHEN classification='bot'     THEN 1 ELSE 0 END) AS bot_blocks,
            SUM(CASE WHEN classification='verified_bot' THEN 1 ELSE 0 END) AS verified_bot_blocks,
            SUM(CASE WHEN classification NOT IN ('bad_bot','ai_bot','bot') THEN 1 ELSE 0 END) AS other_blocks
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
        ";
        $row = $wpdb->get_row($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        return [
            'total_blocks'        => (int)($row['total_blocks']        ?? 0),
            'bad_bot_blocks'      => (int)($row['bad_bot_blocks']      ?? 0),
            'ai_bot_blocks'       => (int)($row['ai_bot_blocks']       ?? 0),
            'verified_bot_blocks' => (int)($row['verified_bot_blocks'] ?? 0),
            'bot_blocks'          => (int)($row['bot_blocks']          ?? 0),
            'other_blocks'        => (int)($row['other_blocks']        ?? 0),
            'hours'               => $hours,
        ];
    }

    public function get_block_reasons_breakdown($hours = 24, $limit = 10) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql_total = "SELECT COUNT(*) FROM $table WHERE event_type='block' AND timestamp_utc >= %s";
        $total = (int)$wpdb->get_var($wpdb->prepare($sql_total, $cutoff));

        $sql = "
          SELECT COALESCE(NULLIF(block_reason,''),'unspecified') AS reason, COUNT(*) AS cnt
          FROM $table
          WHERE event_type='block' AND timestamp_utc >= %s
          GROUP BY reason
          ORDER BY cnt DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $items = [];
        $acc = 0; $n = 0;
        foreach ($rows as $r) {
            $n++;
            if ($n <= $limit) {
                $c = (int)$r['cnt'];
                $acc += $c;
                $items[] = [
                    'reason'  => $r['reason'],
                    'count'   => $c,
                    'percent' => $total ? round($c * 100 / $total, 1) : 0.0,
                ];
            }
        }
        if ($total > $acc) {
            $rest = $total - $acc;
            $items[] = [
                'reason'  => 'other',
                'count'   => $rest,
                'percent' => $total ? round($rest * 100 / $total, 1) : 0.0,
            ];
        }

        return ['total' => $total, 'items' => $items];
    }

    public function get_score_histogram($hours = 24, $bucket_size = 10) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours = max(1, min(720, (int)$hours));
        $bucket_size = max(1, min(50, (int)$bucket_size));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $num_buckets = (int)ceil(100 / $bucket_size);
        $last_idx = $num_buckets - 1;

        $labels = [];
        $human = array_fill(0, $num_buckets, 0);
        $auto  = array_fill(0, $num_buckets, 0);
        $total = array_fill(0, $num_buckets, 0);
        for ($i = 0; $i < $num_buckets; $i++) {
            $start = $i * $bucket_size;
            $end   = ($i === $last_idx) ? 100 : ($i + 1) * $bucket_size - 1;
            $labels[$i] = sprintf('%d–%d', $start, $end);
        }

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            LEAST(FLOOR(score / %d), %d) AS b,
            SUM(CASE WHEN classification='human' THEN 1 ELSE 0 END) AS human_count,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN 1 ELSE 0 END) AS automated_count,
            COUNT(*) AS total_count
          FROM $table
          WHERE event_type IN ('page','fp')
            AND timestamp_utc >= %s
            AND score IS NOT NULL
            AND had_fp = 1
          GROUP BY b
          ORDER BY b
        ";

        $rows = $wpdb->get_results($wpdb->prepare($sql, $bucket_size, $last_idx, $cutoff), ARRAY_A) ?: [];
        foreach ($rows as $r) {
            $idx = (int)$r['b'];
            if ($idx < 0 || $idx > $last_idx) continue;
            $human[$idx] = (int)$r['human_count'];
            $auto[$idx]  = (int)$r['automated_count'];
            $total[$idx] = (int)$r['total_count'];
        }

        $row = $wpdb->get_row($wpdb->prepare("
          SELECT
            SUM(CASE WHEN classification='human' THEN score ELSE 0 END)        AS human_sum,
            SUM(CASE WHEN classification='human' THEN 1 ELSE 0 END)            AS human_n,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN score ELSE 0 END) AS auto_sum,
            SUM(CASE WHEN classification IN ('bad_bot','ai_bot','bot','verified_bot') THEN 1 ELSE 0 END)     AS auto_n
          FROM $table
          WHERE event_type IN ('page','fp') AND had_fp=1 AND timestamp_utc >= %s
        ", $cutoff), ARRAY_A) ?: ['human_sum'=>0,'human_n'=>0,'auto_sum'=>0,'auto_n'=>0];

        $avg_human = ((int)$row['human_n'] > 0) ? round(((float)$row['human_sum']) / (int)$row['human_n'], 1) : null;
        $avg_auto  = ((int)$row['auto_n']  > 0) ? round(((float)$row['auto_sum'])  / (int)$row['auto_n'],  1) : null;

        return [
            'bucket_size'       => $bucket_size,
            'labels'            => $labels,
            'human_counts'      => $human,
            'automated_counts'  => $auto,
            'total_counts'      => $total,
            'hours'             => $hours,
            'avg_human_score'   => $avg_human,
            'avg_auto_score'    => $avg_auto,
        ];
    }

    public function get_ai_bot_user_agents($hours = 24) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours  = max(1, min(720, (int)$hours));
        $cutoff = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            user_agent,
            COUNT(DISTINCT ip) AS unique_ips,
            COUNT(*) AS events
          FROM $table
          WHERE classification='ai_bot' AND timestamp_utc >= %s
          GROUP BY user_agent
          ORDER BY unique_ips DESC, events DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff), ARRAY_A) ?: [];

        $total_unique_ips = (int)$wpdb->get_var($wpdb->prepare(
            "SELECT COUNT(DISTINCT ip) FROM $table WHERE classification='ai_bot' AND timestamp_utc >= %s",
            $cutoff
        ));

        $items = array_map(function($r){
            $ua = (string)$r['user_agent'];
            return [
                'company'    => $this->aiua->get_ai_bot_company($ua),
                'user_agent' => mb_substr($ua, 0, 500),
                'unique_ips' => (int)$r['unique_ips'],
                'events'     => (int)$r['events'],
            ];
        }, $rows);

        return [
            'hours'            => $hours,
            'total_unique_ips' => $total_unique_ips,
            'items'            => $items,
        ];
    }

    public function get_top_factor_histogram($hours = 24, $min_score = 30) {
        global $wpdb;
        $table = $wpdb->prefix . 'baskerville_stats';

        $hours     = max(1, min(720, (int)$hours));
        $min_score = max(0, min(100, (int)$min_score));
        $cutoff    = gmdate('Y-m-d H:i:s', time() - $hours * 3600);

        $wpdb->query("SET time_zone = '+00:00'");

        $sql = "
          SELECT
            top_factor AS factor,
            COUNT(*)   AS cnt,
            AVG(score) AS avg_score
          FROM $table
          WHERE event_type IN ('page','fp')
            AND timestamp_utc >= %s
            AND had_fp = 1
            AND score > %d
            AND top_factor IS NOT NULL
            AND top_factor <> ''
          GROUP BY top_factor
          ORDER BY cnt DESC
        ";
        $rows = $wpdb->get_results($wpdb->prepare($sql, $cutoff, $min_score), ARRAY_A) ?: [];

        $total = 0;
        foreach ($rows as $r) { $total += (int)$r['cnt']; }

        $items = array_map(function($r) use ($total) {
            $cnt = (int)$r['cnt'];
            return [
                'factor'     => (string)$r['factor'],
                'count'      => $cnt,
                'percent'    => $total ? round($cnt * 100 / $total, 1) : 0.0,
                'avg_score'  => round((float)$r['avg_score'], 1),
            ];
        }, $rows);

        return [
            'hours'      => $hours,
            'min_score'  => $min_score,
            'total'      => $total,
            'items'      => $items,
        ];
    }

    /* ===== File-based logging (performance optimization) ===== */

    private function get_log_dir(): string {
        $dir = WP_CONTENT_DIR . '/cache/baskerville/logs';
        if (!is_dir($dir)) {
            @wp_mkdir_p($dir);
        }
        return $dir;
    }

    private function get_log_file_path(): string {
        return $this->get_log_dir() . '/visits-' . gmdate('Y-m-d') . '.log';
    }

    /**
     * Log page visit to file (fast: ~1-2ms)
     * Returns true on success, false on failure
     */
    public function log_page_visit_to_file($ip, $baskerville_id, $evaluation, $classification, $user_agent, $visit_key): bool {
        $log_file = $this->get_log_file_path();

        $fp_cookie = $this->core->read_fp_cookie();
        [$top_json, $top_name] = $this->extract_top_factors((array)$evaluation, $fp_cookie);

        // Get country code for GeoIP analytics
        $country_code = $this->core->get_country_by_ip($ip);

        $data = [
            'visit_key'             => $visit_key,
            'ip'                    => $ip,
            'country_code'          => $country_code,
            'baskerville_id'        => $baskerville_id,
            'timestamp_utc'         => current_time('mysql', true),
            'score'                 => (int)($evaluation['score'] ?? 0),
            'classification'        => (string)($classification['classification'] ?? 'unknown'),
            'user_agent'            => $user_agent,
            'evaluation_json'       => wp_json_encode($evaluation),
            'score_reasons'         => implode('; ', $evaluation['reasons'] ?? []),
            'classification_reason' => (string)($classification['reason'] ?? ''),
            'event_type'            => 'page',
            'top_factor_json'       => $top_json,
            'top_factor'            => $top_name,
        ];

        // Write as single JSON line
        $line = wp_json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

        // Fast append with file lock
        $result = @file_put_contents($log_file, $line, FILE_APPEND | LOCK_EX);

        if ($result === false) {
            error_log('Baskerville: Failed to write to log file: ' . $log_file);
            return false;
        }

        return true;
    }

    /**
     * Process log files and import to database (batch)
     * Called by WP Cron every 5 minutes
     */
    public function process_log_files_to_db(): int {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';
        $log_dir = $this->get_log_dir();

        if (!is_dir($log_dir)) {
            return 0;
        }

        $files = glob($log_dir . '/visits-*.log');
        if (!$files) {
            return 0;
        }

        $total_imported = 0;

        foreach ($files as $file) {
            // Skip today's file if it's being written to
            $today_file = $this->get_log_file_path();
            if ($file === $today_file) {
                continue; // Process tomorrow
            }

            $lines = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!$lines) {
                @unlink($file); // Delete empty file
                continue;
            }

            $batch = [];
            foreach ($lines as $line) {
                $data = json_decode($line, true);
                if (!$data || !isset($data['visit_key'])) {
                    continue; // Skip invalid lines
                }

                $batch[] = $data;

                // Batch insert every 100 records
                if (count($batch) >= 100) {
                    $imported = $this->batch_insert_visits($batch);
                    $total_imported += $imported;
                    $batch = [];
                }
            }

            // Insert remaining records
            if (!empty($batch)) {
                $imported = $this->batch_insert_visits($batch);
                $total_imported += $imported;
            }

            // Delete processed file
            @unlink($file);
        }

        if ($total_imported > 0) {
            error_log("Baskerville: Imported $total_imported page visits from log files");
        }

        return $total_imported;
    }

    /**
     * Batch insert visits to database (optimized)
     */
    private function batch_insert_visits(array $batch): int {
        global $wpdb;
        $table_name = $wpdb->prefix . 'baskerville_stats';

        if (empty($batch)) {
            return 0;
        }

        // Build multi-row INSERT query
        $values = [];
        $placeholders = [];

        foreach ($batch as $data) {
            $placeholders[] = "(%s, %s, %s, %s, %s, %d, %s, %s, %s, %s, %s, %s, %s, %s)";
            $values[] = $data['visit_key'];
            $values[] = $data['ip'];
            $values[] = $data['country_code'];
            $values[] = $data['baskerville_id'];
            $values[] = $data['timestamp_utc'];
            $values[] = (int)$data['score'];
            $values[] = $data['classification'];
            $values[] = $data['user_agent'];
            $values[] = $data['evaluation_json'];
            $values[] = $data['score_reasons'];
            $values[] = $data['classification_reason'];
            $values[] = $data['event_type'];
            $values[] = $data['top_factor_json'];
            $values[] = $data['top_factor'];
        }

        $sql = "INSERT INTO $table_name
                (visit_key, ip, country_code, baskerville_id, timestamp_utc, score, classification,
                 user_agent, evaluation_json, score_reasons, classification_reason, event_type,
                 top_factor_json, top_factor)
                VALUES " . implode(', ', $placeholders);

        $result = $wpdb->query($wpdb->prepare($sql, $values));

        if ($result === false) {
            error_log('Baskerville: Batch insert failed - ' . $wpdb->last_error);
            return 0;
        }

        return $result;
    }

    /**
     * Cleanup old log files (older than 7 days)
     */
    public function cleanup_old_log_files(): int {
        $log_dir = $this->get_log_dir();
        if (!is_dir($log_dir)) {
            return 0;
        }

        $files = glob($log_dir . '/visits-*.log');
        if (!$files) {
            return 0;
        }

        $deleted = 0;
        $cutoff = time() - (7 * 86400); // 7 days

        foreach ($files as $file) {
            $mtime = @filemtime($file);
            if ($mtime && $mtime < $cutoff) {
                if (@unlink($file)) {
                    $deleted++;
                }
            }
        }

        if ($deleted > 0) {
            error_log("Baskerville: Deleted $deleted old log files");
        }

        return $deleted;
    }
}
