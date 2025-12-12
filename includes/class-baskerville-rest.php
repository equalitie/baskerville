<?php

class Baskerville_REST {
    private Baskerville_Core $core;
    private Baskerville_AI_UA $aiua;
    private Baskerville_Stats $stats;

    public function __construct(
        Baskerville_Core $core,
        Baskerville_Stats $stats,
        Baskerville_AI_UA $aiua
    ) {
        $this->core  = $core;
        $this->stats = $stats;
        $this->aiua  = $aiua;
    }

    public function register_routes() {
        // error_log('Baskerville: registering REST routes');

        register_rest_route('baskerville/v1', '/fp', [
            'methods'             => WP_REST_Server::CREATABLE,
            'callback'            => [$this, 'handle_fp'],
            'permission_callback' => function () { return true; }, // public endpoint; nonce checked inside
        ]);

        register_rest_route('baskerville/v1', '/stats', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'handle_stats'],
            'permission_callback' => function () { return true; },
        ]);

        register_rest_route('baskerville/v1', '/stats/data', [
            'methods'             => WP_REST_Server::READABLE,
            'callback'            => [$this, 'handle_stats_data'],
            'permission_callback' => function () { return true; },
        ]);
    }

    /**
     * Check API rate limiting
     * Returns WP_REST_Response with 429 if rate limit exceeded, null otherwise
     */
    private function check_api_rate_limit() {
        $options = get_option('baskerville_settings', array());
        $rate_limit_enabled = isset($options['api_rate_limit_enabled']) ? $options['api_rate_limit_enabled'] : true;

        if (!$rate_limit_enabled) {
            return null; // Rate limiting disabled
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));

        // Check if IP is whitelisted
        if ($this->core->is_whitelisted_ip($ip)) {
            return null; // Whitelisted IPs bypass rate limiting
        }

        $max_requests = isset($options['api_rate_limit_requests']) ? (int)$options['api_rate_limit_requests'] : 100;
        $window_sec = isset($options['api_rate_limit_window']) ? (int)$options['api_rate_limit_window'] : 60;

        $key = "api_ratelimit:{$ip}";
        $count = $this->core->fc_inc_in_window($key, $window_sec);

        if ($count > $max_requests) {
            return new WP_REST_Response([
                'error' => 'rate_limit_exceeded',
                'message' => sprintf('Rate limit exceeded. Maximum %d requests per %d seconds.', $max_requests, $window_sec),
                'retry_after' => $window_sec
            ], 429);
        }

        return null;
    }

    public function handle_fp( WP_REST_Request $request ) {
        // Check rate limit
        $rate_limit_response = $this->check_api_rate_limit();
        if ($rate_limit_response) {
            return $rate_limit_response;
        }
        $nonce = $request->get_header('x-wp-nonce');
        if ($nonce && !wp_verify_nonce($nonce, 'wp_rest')) {
            return new WP_REST_Response(['error' => 'invalid_nonce'], 403);
        }

        $body = $request->get_json_params();
        if (empty($body)) {
            return new WP_REST_Response(['error' => 'empty_payload'], 400);
        }

        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
        $headers = [
            'accept'          => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT'] ?? '')),
            'accept_language' => sanitize_text_field(wp_unslash($_SERVER['HTTP_ACCEPT_LANGUAGE'] ?? '')),
            'user_agent'      => sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'] ?? '')),
            'sec_ch_ua'       => sanitize_text_field(wp_unslash($_SERVER['HTTP_SEC_CH_UA'] ?? '')),
            'server_protocol' => sanitize_text_field(wp_unslash($_SERVER['SERVER_PROTOCOL'] ?? '')),
        ];
        $cookie_id = $this->core->get_cookie_id();

        // calculate
        try {
            $evaluation     = $this->aiua->baskerville_score_fp($body, ['headers' => $headers]);
            $classification = $this->aiua->classify_client($body, ['headers' => $headers]);
        } catch (Exception $e) {
            // error_log('Baskerville evaluation error: ' . $e->getMessage());
            $evaluation = ['score' => 0, 'action' => 'error', 'reasons' => ['evaluation_error'], 'top_factors' => []];
            $classification = ['classification' => 'unknown', 'reason' => 'Classification error', 'risk_score' => 0];
        }

        // fp cookie (HttpOnly, signed)
        $ua      = $headers['user_agent'] ?? '';
        $ua_hash = sha1((string)$ua);
        $ttl_sec = 6 * 60 * 60;

        // ! IMPORTANT: assumes that core provides public methods:
        // cookie_secret(), ip_key(), b64u_enc(). If they are private — create public equivalents.
        $payload_fp = [
            'v'     => 1,
            'ts'    => time(),
            'ttl'   => $ttl_sec,
            'ipk'   => $this->core->ip_key($ip),
            'ua'    => substr($ua_hash, 0, 16),
            'bid'   => substr($cookie_id ?: '', 0, 16),
            'score' => (int)($evaluation['score'] ?? 0),
            'top'   => array_map(function ($x) {
                return [
                    'key'   => (string)($x['key']   ?? ''),
                    'delta' => (int)   ($x['delta'] ?? 0),
                    'why'   => (string)($x['why']   ?? ''),
                ];
            }, array_slice($evaluation['top_factors'] ?? [], 0, 6)),
        ];
        $raw = wp_json_encode($payload_fp, JSON_UNESCAPED_SLASHES);
        $sig = hash_hmac('sha256', $raw, $this->core->cookie_secret());
        $val = $this->core->b64u_enc($raw) . '.' . $sig;

        setcookie('baskerville_fp', $val, [
            'expires'  => time() + $ttl_sec,
            'path'     => '/',
            'secure'   => function_exists('wp_is_using_https') ? wp_is_using_https() : is_ssl(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);

        // mark fp seen
        if ($ip)        { $this->core->fc_set("fp_seen_ip:{$ip}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180)); }
        if ($cookie_id) { $this->core->fc_set("fp_seen_cookie:{$cookie_id}", 1, (int) get_option('baskerville_fp_seen_ttl_sec', 180)); }
        $this->core->fc_delete("nojs_cnt:{$ip}");

        $fp_hash   = isset($body['fingerprintHash']) ? substr((string)$body['fingerprintHash'], 0, 64) : null;
        $visit_key = isset($body['visitKey']) ? preg_replace('~[^a-f0-9]~i', '', (string)$body['visitKey']) : '';

        if ($visit_key) {
            $this->stats->update_visit_stats_by_key($visit_key, $evaluation, $classification, $fp_hash);
            return new WP_REST_Response([
                'ok'             => true,
                'score'          => (int)($evaluation['score'] ?? 0),
                'action'         => $evaluation['action'] ?? 'allow',
                'why'            => $evaluation['reasons'] ?? [],
                'classification' => $classification,
            ], 200);
        }

        // fallback: attach to last page hit without FP
        global $wpdb;
        $table = esc_sql( $wpdb->prefix . 'baskerville_stats' );
        $wpdb->query("SET time_zone = '+00:00'");

        $attach_window_sec = (int) get_option('baskerville_fp_attach_window_sec', 180);
        $row_id = null;
        if ($ip && $cookie_id) {
            $row_id = $wpdb->get_var(
                $wpdb->prepare(
                      "SELECT id FROM %i
                        WHERE ip=%s AND baskerville_id=%s AND event_type='page' AND had_fp=0
                          AND timestamp_utc >= DATE_SUB(UTC_TIMESTAMP(), INTERVAL %d SECOND)
                        ORDER BY timestamp_utc DESC LIMIT 1",
                      $table,
                      $ip,
                      $cookie_id,
                      $attach_window_sec
                  )
            );
        }

        [$top_json, $top_name] = $this->stats->extract_top_factors($evaluation, $this->core->read_fp_cookie());
        $score = (int)($evaluation['score'] ?? 0);
        $cls   = (string)($classification['classification'] ?? 'unknown');
        $why   = implode('; ', $evaluation['reasons'] ?? []);
        $cls_r = (string)($classification['reason'] ?? '');

        if ($row_id) {
            $wpdb->update(
                $table,
                [
                    'score'                 => $score,
                    'classification'        => $cls,
                    'evaluation_json'       => wp_json_encode($evaluation),
                    'score_reasons'         => $why,
                    'classification_reason' => $cls_r,
                    'had_fp'                => 1,
                    'fp_received_at'        => current_time('mysql', true),
                    'fingerprint_hash'      => $fp_hash,
                    'top_factor_json'       => $top_json,
                    'top_factor'            => $top_name,
                ],
                ['id' => (int)$row_id],
                ['%d','%s','%s','%s','%s','%d','%s','%s','%s','%s'],
                ['%d']
            );
        } else {
            $visit_key_new = hash('sha256', ($ip ?: '') . '|' . ($cookie_id ?: '') . '|' . microtime(true) . '|' . wp_generate_uuid4());
            $wpdb->insert(
                $table,
                [
                    'visit_key'             => $visit_key_new,
                    'ip'                    => $ip ?: '',
                    'baskerville_id'        => $cookie_id ?: '',
                    'timestamp_utc'         => current_time('mysql', true),
                    'score'                 => $score,
                    'classification'        => $cls,
                    'user_agent'            => $headers['user_agent'] ?? '',
                    'evaluation_json'       => wp_json_encode($evaluation),
                    'score_reasons'         => $why,
                    'classification_reason' => $cls_r,
                    'event_type'            => 'page',
                    'had_fp'                => 1,
                    'fp_received_at'        => current_time('mysql', true),
                    'fingerprint_hash'      => $fp_hash,
                    'top_factor_json'       => $top_json,
                    'top_factor'            => $top_name,
                ],
                ['%s','%s','%s','%s','%d','%s','%s','%s','%s','%s','%d','%s','%s','%s']
            );
        }

        return new WP_REST_Response([
            'ok'             => true,
            'score'          => $score,
            'action'         => $evaluation['action'] ?? 'allow',
            'why'            => $evaluation['reasons'] ?? [],
            'classification' => $classification,
        ], 200);
    }

    public function handle_stats( WP_REST_Request $request ) {
        // Check rate limit
        $rate_limit_response = $this->check_api_rate_limit();
        if ($rate_limit_response) {
            return $rate_limit_response;
        }

        // Return HTML page for statistics visualization
        $stats_url = rest_url('baskerville/v1/stats/data');

        if (!headers_sent()) {
            header('Content-Type: text/html; charset=UTF-8');
        }

        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Baskerville Statistics</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js" integrity="sha384-jGsMQM3myBVH/uFd4WWKE8E6TSqJ3p9V0OYFBYhD1LmJLcW3e+1bLQjMQPCBrJMb" crossorigin="anonymous"></script>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background: #f5f5f5;
                    color: #333;
                }
                .container {
                    max-width: 1200px;
                    margin: 0 auto;
                    background: white;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                    padding: 30px;
                }
                h1 {
                    text-align: center;
                    color: #2c3e50;
                    margin-bottom: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    gap: 10px;
                }
                .stats-grid {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }
                .stat-card.human { background: linear-gradient(135deg, #4CAF50 0%, #45a049 100%); }
                .stat-card.bot { background: linear-gradient(135deg, #FF9800 0%, #F57C00 100%); }
                .stat-card.ai-bot { background: linear-gradient(135deg, #ff9800 0%, #f57c00 100%); }
                .stat-card.score { background: linear-gradient(135deg, #2196F3 0%, #1976D2 100%); }
                .stat-card.block { background: linear-gradient(135deg, #e53935 0%, #d32f2f 100%); }

                .stat-number {
                    font-size: 2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                .stat-label {
                    font-size: 0.9em;
                    opacity: 0.9;
                }
                .chart-container {
                    margin: 30px 0;
                    height: 400px;
                }
                .controls {
                    display: flex;
                    gap: 10px;
                    margin-bottom: 20px;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                .control-button {
                    padding: 8px 16px;
                    border: none;
                    border-radius: 4px;
                    background: #3498db;
                    color: white;
                    cursor: pointer;
                    transition: background 0.3s;
                }
                .control-button:hover {
                    background: #2980b9;
                }
                .control-button.active {
                    background: #2c3e50;
                }
                .loading {
                    text-align: center;
                    padding: 20px;
                    color: #666;
                }
              .charts-row {
                display: grid;
                grid-template-columns: 2fr 1fr;
                gap: 20px;
                align-items: stretch;
                margin-top: 10px;
              }
              .baskerville-logo{
                  height: 46px;      /* подгоните при желании */
                  width: auto;
                  object-fit: contain;
                  display: block;    /* чтобы в флексе не прыгал */
              }
                .table-ua { width:100%; border-collapse:collapse; }
                .table-ua th, .table-ua td { padding:8px; border-bottom:1px solid #eee; vertical-align:top; }
                .table-ua th { text-align:left; font-weight:600; color:#2c3e50; }
                .table-ua td.num { text-align:right; white-space:nowrap; }
                .table-ua td.ua { word-break:break-word; }
                .badge { display:inline-block; padding:2px 8px; border-radius:999px; background:#f0f3f7; font-size:.85em; color:#455a64; }

              .chart-half {
                background: #fff;
                border-radius: 8px;
                box-shadow: 0 1px 6px rgba(0,0,0,0.06);
                padding: 14px;
                height: 360px;
              }
              @media (max-width: 900px) {
                .charts-row { grid-template-columns: 1fr; }
                .chart-half { height: 320px; }
              }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>
                  <img
                    src="<?php echo esc_url( BASKERVILLE_PLUGIN_URL . 'assets/logo-baskerville.png?v=' . BASKERVILLE_VERSION ); ?>"
                    alt="Baskerville"
                    class="baskerville-logo"
                  />
                  Baskerville
                </h1>

                <div id="summary-stats" class="stats-grid">
                    <div class="loading">Loading statistics...</div>
                </div>

                <div class="controls">
                    <button class="control-button active" onclick="loadData(24)">24 Hours</button>
                    <button class="control-button" onclick="loadData(72)">3 Days</button>
                    <button class="control-button" onclick="loadData(168)">7 Days</button>
                    <button class="control-button" onclick="loadData(336)">14 Days</button>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="humAutoBar"></canvas>
                  </div>
                  <div class="chart-half">
                    <canvas id="humAutoPie"></canvas>
                  </div>
                </div>
                <div class="chart-container">
                    <canvas id="trafficChart"></canvas>
                </div>
                <div class="chart-container">
                  <canvas id="blocksChart"></canvas>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="blockReasonsPie"></canvas>
                  </div>
                  <div class="chart-half" id="blockReasonsTable" style="overflow:auto"></div>
                </div>
                <div class="chart-container" style="height:auto;">
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">
                    <div style="font-weight:600;">AI bot User-Agents — unique IPs (last <span id="aiUAHours">24</span>h)</div>
                    <input id="aiUAFilter" type="search" placeholder="Filter by Company or UA…" style="padding:6px 10px;border:1px solid #ddd;border-radius:6px;min-width:240px;">
                  </div>
                  <div id="aiUAList" style="overflow:auto; max-height: 420px;"></div>
                </div>

                <div class="chart-container">
                  <canvas id="scoreHistChart"></canvas>
                </div>
                <div class="charts-row">
                  <div class="chart-half">
                    <canvas id="topFactorBar"></canvas>
                  </div>
                  <div class="chart-half" id="topFactorTable" style="overflow:auto"></div>
                </div>



            </div>

            <script>
                let chart = null;
                let currentHours = 24;
                 let chartHumAuto = null;
                 let chartHumAutoPie = null;
                 let chartBlocks = null;
                 let chartScoreHist = null;

                const STATS_URL = '<?php echo esc_js($stats_url); ?>';

                function updateTopFactorHistogram(tf) {
                  const el = document.getElementById('topFactorBar');
                  const tbl = document.getElementById('topFactorTable');
                  if (!el || !tf) return;

                  const labels = (tf.items || []).map(i => i.factor);
                  const counts = (tf.items || []).map(i => i.count);
                  const avgs   = (tf.items || []).map(i => i.avg_score);
                  const share  = (tf.items || []).map(i => i.percent);

                  // Гистограмма по счётчикам (bar). В тултипе — доля и средний скор.
                  if (window.chartTopFactor) window.chartTopFactor.destroy();
                  window.chartTopFactor = new Chart(el.getContext('2d'), {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [{
                        label: 'Count (score > ' + (tf.min_score ?? 30) + ')',
                        data: counts,
                        backgroundColor: '#9C27B0', // фиолетовый, чтобы не путать с Humans/Automated
                        borderColor: '#9C27B0',
                        borderWidth: 1
                      }]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { title: { display: true, text: 'Top factor' } },
                        y: { beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Top factors — score > ' + (tf.min_score ?? 30) + ' (last ' + (tf.hours ?? '') + 'h)' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const i = items[0].dataIndex;
                              return [
                                'Share: ' + (share[i] || 0) + '%',
                                'Avg score: ' + (avgs[i] ?? '—')
                              ];
                            }
                          }
                        },
                        legend: { display: false }
                      }
                    }
                  });

                  // Мини-таблица (топ 20, если их много)
                  if (tbl) {
                    const rows = (tf.items || []).slice(0, 20).map(i =>
                      `<tr>
                         <td>${escHtml(i.factor)}</td>
                         <td style="text-align:right;">${i.count}</td>
                         <td style="text-align:right;">${i.percent}%</td>
                         <td style="text-align:right;">${i.avg_score}</td>
                       </tr>`
                    ).join('');
                    tbl.innerHTML = `
                      <div style="font-weight:600;margin-bottom:8px;">
                        Top factors (score > ${tf.min_score ?? 30}) — last ${tf.hours ?? ''}h
                        <span class="badge">Total: ${tf.total || 0}</span>
                      </div>
                      <table style="width:100%;border-collapse:collapse;">
                        <thead>
                          <tr>
                            <th style="text-align:left;border-bottom:1px solid #eee;padding:6px 0;">Factor</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Count</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Share</th>
                            <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Avg score</th>
                          </tr>
                        </thead>
                        <tbody>${rows || `<tr><td colspan="4" style="padding:10px;color:#777;">No data</td></tr>`}</tbody>
                      </table>
                    `;
                  }
                }

                function updateScoreHistogram(hist) {
                  const el = document.getElementById('scoreHistChart');
                  if (!el || !hist) return;
                  const ctx = el.getContext('2d');
                  if (chartScoreHist) chartScoreHist.destroy();

                  const labels = hist.labels || [];
                  const humans = hist.human_counts || hist.humanCounts || [];
                  const autos  = hist.automated_counts || hist.automatedCounts || [];
                  const bucketSize = Number(hist.bucket_size || 10);

                  const avgFromBuckets = (labels, counts) => {
                    let sum = 0, tot = 0;
                    labels.forEach((lab, i) => {
                      const m = String(lab).match(/(\d+)[–-](\d+)/);
                      if (!m) return;
                      const mid = (parseInt(m[1], 10) + parseInt(m[2], 10)) / 2;
                      const c = counts[i] || 0;
                      sum += mid * c; tot += c;
                    });
                    return tot ? (sum / tot) : null;
                  };

                  const avgH = avgFromBuckets(labels, humans);
                  const avgA = avgFromBuckets(labels, autos);

                  // helper: rounded rect
                  const roundRect = (ctx, x, y, w, h, r) => {
                    const rr = Math.min(r, w/2, h/2);
                    ctx.beginPath();
                    ctx.moveTo(x + rr, y);
                    ctx.arcTo(x + w, y, x + w, y + h, rr);
                    ctx.arcTo(x + w, y + h, x, y + h, rr);
                    ctx.arcTo(x, y + h, x, y, rr);
                    ctx.arcTo(x, y, x + w, y, rr);
                    ctx.closePath();
                  };

                  const avgLinesPlugin = {
                    id: 'avgLines',
                    afterDatasetsDraw(chart) {
                      const { ctx, chartArea, scales } = chart;
                      const x = scales.x;
                      const yTop = chartArea.top;
                      const yBottom = chartArea.bottom;

                      const drawAvg = (val, color, label, yOffset) => {
                        if (val == null || isNaN(val)) return;

                        let idx = Math.floor(val / bucketSize);
                        idx = Math.max(0, Math.min(labels.length - 1, idx));
                        const xPix = x.getPixelForValue(idx);

                        // линия
                        ctx.save();
                        ctx.setLineDash([6, 6]);
                        ctx.strokeStyle = color;
                        ctx.lineWidth = 2;
                        ctx.beginPath();
                        ctx.moveTo(xPix, yTop);
                        ctx.lineTo(xPix, yBottom);
                        ctx.stroke();
                        ctx.setLineDash([]);

                        // подпись с серой подложкой
                        ctx.font = '12px system-ui, -apple-system, Segoe UI, Roboto, sans-serif';
                        const pad = 6;
                        const text = label;
                        const metrics = ctx.measureText(text);
                        const textW = metrics.width;
                        const textH = 16; // примерно для 12px шрифта

                        // стараемся не выходить за край
                        const prefersLeft = (chartArea.right - xPix) < (textW + 12) && (xPix - chartArea.left) > (textW + 12);
                        let textX = prefersLeft ? (xPix - textW - pad) : (xPix + pad);
                        textX = Math.max(chartArea.left + 2, Math.min(textX, chartArea.right - textW - 2));
                        const textY = yTop + (yOffset || 4);

                        // тень/фон
                        ctx.fillStyle = 'rgba(0,0,0,0.15)';
                        roundRect(ctx, textX - 4, textY - 2, textW + 8, textH, 4);
                        ctx.fill();

                        // собственно текст
                        ctx.fillStyle = color;
                        ctx.textBaseline = 'top';
                        ctx.fillText(text, textX, textY);
                        ctx.restore();
                      };

                      // зелёная выше, оранжевая ниже
                      drawAvg(avgH, '#4CAF50', `avg human ${avgH?.toFixed(1)}`, 4);
                      drawAvg(avgA, '#FF9800', `avg automated ${avgA?.toFixed(1)}`, 24);
                    }
                  };

                  chartScoreHist = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        {
                          label: 'Humans',
                          data: humans,
                          backgroundColor: '#4CAF50',
                          borderColor: '#4CAF50',
                          borderWidth: 1
                        },
                        {
                          label: 'Automated',
                          data: autos,
                          backgroundColor: '#FF9800',
                          borderColor: '#FF9800',
                          borderWidth: 1
                        }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      layout: { padding: { top: 32 } }, // больше места под обе подписи
                      scales: {
                        x: { stacked: false, title: { display: true, text: 'Score buckets (width = ' + bucketSize + ')' } },
                        y: { beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Score Distribution — last ' + (hist.hours || '') + 'h' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const idx = items[0].dataIndex;
                              const h = humans[idx] || 0, a = autos[idx] || 0, t = h + a;
                              const hp = t ? Math.round((h * 100) / t) : 0;
                              const ap = t ? Math.round((a * 100) / t) : 0;
                              return [`Total: ${t}`, `Humans: ${h} (${hp}%)`, `Automated: ${a} (${ap}%)`];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    },
                    plugins: [avgLinesPlugin]
                  });
                }

                                                // безопасный вывод текста в HTML
                function escHtml(s){
                  return String(s || '')
                    .replaceAll('&','&amp;')
                    .replaceAll('<','&lt;')
                    .replaceAll('>','&gt;')
                    .replaceAll('"','&quot;')
                    .replaceAll("'",'&#39;');
                }

                let __aiUAData = null;

                function renderAIBotUAList(data, filterText='') {
                  const el = document.getElementById('aiUAList');
                  const hrs = document.getElementById('aiUAHours');
                  if (!el || !data) return;

                  if (hrs) hrs.textContent = String(data.hours || currentHours);

                  const items = (data.items || []);
                  const f = (filterText || '').trim().toLowerCase();
                  const filtered = f ? items.filter(it => (it.user_agent||'').toLowerCase().includes(f) || (it.company||'').toLowerCase().includes(f)) : items;

                  if (!filtered.length) {
                    el.innerHTML = `<div style="color:#777;padding:10px;">No AI-bot user agents${f ? ' for filter "'+escHtml(filterText)+'"' : ''}.</div>`;
                    return;
                  }

                  const rows = filtered.map(it => {
                    const ua = escHtml(it.user_agent || '');
                    const company = escHtml(it.company || 'Unknown');
                    return `<tr>
                      <td style="width:120px;font-weight:600;color:#2c3e50;">${company}</td>
                      <td class="ua"><span title="${ua}">${ua}</span></td>
                      <td class="num">${it.unique_ips}</td>
                      <td class="num">${it.events}</td>
                    </tr>`;
                  }).join('');

                  el.innerHTML = `
                    <table class="table-ua">
                      <thead>
                        <tr>
                          <th style="width:120px;">Company</th>
                          <th>User-Agent</th>
                          <th style="width:140px;">Unique IPs</th>
                          <th style="width:120px;">Events</th>
                        </tr>
                      </thead>
                      <tbody>${rows}</tbody>
                      <tfoot>
                        <tr>
                          <td colspan="2"><span class="badge">Total unique IPs (all AI): ${data.total_unique_ips || 0}</span></td>
                          <td class="num" colspan="2"><span class="badge">${filtered.length} UA rows</span></td>
                        </tr>
                      </tfoot>
                    </table>
                  `;
                }

                function updateAIBotUAList(aiUA){
                  __aiUAData = aiUA || {items:[]};
                  console.log('AI UA Data:', __aiUAData); // Debug: проверим данные
                  renderAIBotUAList(__aiUAData, document.getElementById('aiUAFilter')?.value || '');
                }

                // live-фильтр
                document.addEventListener('input', (e)=>{
                  if (e.target && e.target.id === 'aiUAFilter') {
                    renderAIBotUAList(__aiUAData, e.target.value);
                  }
                });

                function updateBlocksChart(blocksSeries) {
                  const el = document.getElementById('blocksChart');
                  if (!el) return;
                  const ctx = el.getContext('2d');
                  if (window.chartBlocks) window.chartBlocks.destroy();

                  const labels  = blocksSeries.map(i => fmtHHMM(i.time));
                  const bad     = blocksSeries.map(i => i.bad_bot_blocks    || 0);
                  const ai      = blocksSeries.map(i => i.ai_bot_blocks     || 0);
                  const bot     = blocksSeries.map(i => i.bot_blocks        || 0);
                  const other   = blocksSeries.map(i => i.other_blocks      || 0);
                  const verified= blocksSeries.map(i => i.verified_bot_blocks || 0);
                  const totals  = blocksSeries.map(i => i.total_blocks      || 0);

                  window.chartBlocks = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: '403 Bad bots',           data: bad,      stack: 'blocks', backgroundColor: '#ff6b6b' },
                        { label: '403 AI bots',            data: ai,       stack: 'blocks', backgroundColor: '#ff9800' },
                        { label: '403 Bots',               data: bot,      stack: 'blocks', backgroundColor: '#673AB7' },
                        { label: '403 Other',              data: other,    stack: 'blocks', backgroundColor: '#90A4AE' },
                        { label: '403 Verified crawlers',  data: verified, stack: 'blocks', backgroundColor: '#03A9F4' }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { stacked: true, title: { display: true, text: 'Time, UTC' } },
                        y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Blocked decisions (403)' } }
                      },
                      plugins: {
                        title: { display: true, text: '403 Decisions by Bot Category — last ' + currentHours + 'h' },
                        tooltip: {
                          callbacks: {
                            afterBody(items) {
                              const idx = items[0].dataIndex;
                              return ['Total 403: ' + (totals[idx] || 0)];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    }
                  });
                }

                // Возвращает HH:MM из строки вида "YYYY-MM-DD HH:MM:SS" (или любой строки с временем)
                function fmtHHMM(ts) {
                  const m = String(ts || '').match(/\b(\d{2}):(\d{2})/);
                  return m ? m[1] + ':' + m[2] : String(ts || '');
                }

                async function loadData(hours = 24) {
                    try {
                        currentHours = hours;

                        const t = (typeof event !== 'undefined' && event && event.target) ? event.target : null;
                        document.querySelectorAll('.control-button').forEach(btn => btn.classList.remove('active'));
                        if (t) t.classList.add('active');

                        const response = await fetch(STATS_URL + '?hours=' + hours + '&_=' + Date.now(), { cache: 'no-store' });

                        const data = await response.json();
                        updateSummaryStats(data.summary_window || data.summary, data.blocks_summary, data.block_reasons);
                        updateHumAutoCharts(data.timeseries);
                        updateChart(data.timeseries);
                        updateBlockReasons(data.block_reasons || { total:0, items:[] });
                        updateBlocksChart(data.timeseries_blocks || []);
                        updateScoreHistogram(data.score_histogram);
                        updateAIBotUAList(data.ai_ua);
                        updateTopFactorHistogram(data.top_factor_histogram);

                    } catch (error) {
                        console.error('Error loading data:', error);
                    }
                }

                function updateBlockReasons(reasons) {
                  // Pie
                  const elPie = document.getElementById('blockReasonsPie');
                  if (elPie) {
                    const ctx = elPie.getContext('2d');
                    if (window.chartBlockReasonsPie) window.chartBlockReasonsPie.destroy();

                    const labels = (reasons.items || []).map(i => i.reason);
                    const data   = (reasons.items || []).map(i => i.count);

                    window.chartBlockReasonsPie = new Chart(ctx, {
                      type: 'pie',
                      data: { labels, datasets: [{ data }] },
                      options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                          title: { display: true, text: '403 by Reason — last ' + currentHours + 'h' },
                          tooltip: {
                            callbacks: {
                              label: (c) => ' ' + c.label + ': ' + c.parsed + ' (' + ((c.parsed/(reasons.total||1))*100).toFixed(1) + '%)'
                            }
                          },
                          legend: { position: 'bottom' }
                        }
                      }
                    });
                  }

                  // Table
                  const elTbl = document.getElementById('blockReasonsTable');
                  if (elTbl) {
                    const total = reasons.total || 0;
                    const rows = (reasons.items || []).map(i =>
                      '<tr><td>' + i.reason + '</td><td style="text-align:right;">' + i.count + '</td><td style="text-align:right;">' + i.percent + '%</td></tr>'
                    ).join('');
                    elTbl.innerHTML = `
                      <div style="font-weight:600;margin-bottom:8px;">403 Reasons — totals</div>
                      <table style="width:100%;border-collapse:collapse;">
                        <thead><tr>
                          <th style="text-align:left;border-bottom:1px solid #eee;padding:6px 0;">Reason</th>
                          <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Count</th>
                          <th style="text-align:right;border-bottom:1px solid #eee;padding:6px 0;">Share</th>
                        </tr></thead>
                        <tbody>${rows || `<tr><td colspan="3" style="padding:10px;color:#777;">No data</td></tr>`}</tbody>
                        <tfoot>
                          <tr><td style="border-top:1px solid #eee;padding:6px 0;">Total</td>
                              <td style="text-align:right;border-top:1px solid #eee;padding:6px 0;">${total}</td>
                              <td style="text-align:right;border-top:1px solid #eee;padding:6px 0;">100%</td></tr>
                        </tfoot>
                      </table>
                    `;
                  }
                }


                function updateSummaryStats(summaryLike, blocksSummary, reasons) {
                  const blocked = (blocksSummary && blocksSummary.total_blocks) ? blocksSummary.total_blocks : 0;
                  const humanPct = summaryLike?.human_percentage || 0;
                  const botPct   = summaryLike?.bot_percentage || 0;

                  const top3 = (reasons && reasons.items ? reasons.items.slice(0,3) : []);
                  const mini = top3.length
                    ? `<div style="font-size:.85em;margin-top:8px;text-align:left;">
                         <div style="opacity:.9;margin-bottom:4px;">Top reasons:</div>
                         ${top3.map(i => `<div>• ${i.reason}: ${i.count} (${i.percent}%)</div>`).join('')}
                       </div>`
                    : '';

                  const statsHtml = `
                    <div class="stat-card">
                      <div class="stat-number">${summaryLike.total_visits || 0}</div>
                      <div class="stat-label">Total Visits — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card human">
                      <div class="stat-number">${humanPct}%</div>
                      <div class="stat-label">Human Traffic — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card bot">
                      <div class="stat-number">${botPct}%</div>
                      <div class="stat-label">Automated Traffic — last ${currentHours}h</div>
                    </div>
                    <div class="stat-card block">
                      <div class="stat-number">${blocked}</div>
                      <div class="stat-label">Blocked (403) — last ${currentHours}h</div>
                      ${mini}
                    </div>
                  `;
                  document.getElementById('summary-stats').innerHTML = statsHtml;
                }

                function updateHumAutoCharts(timeseries) {
                  const barCtx = document.getElementById('humAutoBar')?.getContext('2d');
                  const pieCtx = document.getElementById('humAutoPie')?.getContext('2d');
                  if (!barCtx || !pieCtx) return;

                  // Сбор данных
                  const labels = timeseries.map(i => fmtHHMM(i.time));
                  const humans = timeseries.map(i => i.human_count || 0);
                  const automated = timeseries.map(i =>
                      (i.bad_bot_count||0) + (i.ai_bot_count||0) + (i.bot_count||0) + (i.verified_bot_count||0)
                    );


                  // Totals для круговой диаграммы — за выбранный период (а не retention_days)
                  const totalHumans = humans.reduce((a,b) => a+b, 0);
                  const totalAutomated = automated.reduce((a,b) => a+b, 0);

                  // Пересоздаём графики, если уже были
                  if (chartHumAuto) chartHumAuto.destroy();
                  if (chartHumAutoPie) chartHumAutoPie.destroy();

                  // 1) Stacked Bar: Humans vs Automated
                  chartHumAuto = new Chart(barCtx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: 'Humans',    data: humans,    stack: 'visits2', backgroundColor: '#4CAF50' },
                        { label: 'Automated', data: automated, stack: 'visits2', backgroundColor: '#FF9800' }
                      ]
                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: { stacked: true, title: { display: true, text: 'Time, UTC' } },
                        y: { stacked: true, beginAtZero: true, title: { display: true, text: 'Visits' } }
                      },
                      plugins: {
                        title: { display: true, text: 'Humans vs Automated — last ' + currentHours + 'h' },
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
                        },
                        legend: { display: true }
                      }
                    }
                  });

                  // 2) Pie: Totals Humans vs Automated
                  chartHumAutoPie = new Chart(pieCtx, {
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
                      maintainAspectRatio: false,
                      plugins: {
                        title: { display: true, text: 'Totals — last ' + currentHours + 'h' },
                        tooltip: {
                          callbacks: {
                            label(ctx) {
                              const v = ctx.parsed || 0;
                              const sum = totalHumans + totalAutomated || 1;
                              const pct = Math.round((v*100)/sum);
                              return ` ${ctx.label}: ${v} (${pct}%)`;
                            }
                          }
                        },
                        legend: { position: 'bottom' }
                      }
                    }
                  });
                }

                function updateChart(timeseries) {
                  const ctx = document.getElementById('trafficChart').getContext('2d');
                  if (chart) chart.destroy();

                  const labels = timeseries.map(i => fmtHHMM(i.time));
                  const humans   = timeseries.map(i => i.human_count || 0);
                  const badBots  = timeseries.map(i => i.bad_bot_count || 0);
                  const aiBots   = timeseries.map(i => i.ai_bot_count || 0);
                  const bots     = timeseries.map(i => i.bot_count || 0);
                  const verified = timeseries.map(i => i.verified_bot_count || 0);

                  chart = new Chart(ctx, {
                    type: 'bar',
                    data: {
                      labels,
                      datasets: [
                        { label: 'Humans',   data: humans,  stack: 'visits', backgroundColor: '#4CAF50' },
                        { label: 'Bad bots', data: badBots, stack: 'visits', backgroundColor: '#ff6b6b' },
                        { label: 'AI bots',  data: aiBots,  stack: 'visits', backgroundColor: '#ff9800' }, // оранжевый
                        { label: 'Bots',     data: bots,    stack: 'visits', backgroundColor: '#673AB7' }, // фиолетовый, явно отличается
                        { label: 'Verified crawlers', data: verified, stack: 'visits', backgroundColor: '#03A9F4' }
                      ]

                    },
                    options: {
                      responsive: true,
                      maintainAspectRatio: false,
                      interaction: { mode: 'index', intersect: false },
                      scales: {
                        x: {
                          stacked: true,
                          title: { display: true, text: 'Time, UTC' }
                        },
                        y: {
                          stacked: true,
                          beginAtZero: true,
                          title: { display: true, text: 'Visits' }
                        }
                      },
                      plugins: {
                        title: { display: true, text: 'Traffic Analysis - Last ' + currentHours + ' Hours' },
                        tooltip: {
                          callbacks: {
                            // показываем сводку по слотам без процентов
                            afterBody: function(items) {
                              const idx = items[0].dataIndex;
                              const it  = timeseries[idx];
                              return [
                                `Total: ${it.total_visits}`,
                                `Humans: ${it.human_count} | Bad: ${it.bad_bot_count} | AI: ${it.ai_bot_count} | Bots: ${it.bot_count}`,
                                `Avg score: ${it.avg_score}`
                              ];
                            }
                          }
                        },
                        legend: { display: true }
                      }
                    }
                  });
                }

                // Load initial data
                loadData(24);

                // Auto-refresh every 5 minutes
                setInterval(() => loadData(currentHours), 5 * 60 * 1000);
            </script>
        </body>
        </html>
        <?php
        ob_end_flush();
        exit;
    }

    public function handle_stats_data( WP_REST_Request $request ) {
        // Check rate limit
        $rate_limit_response = $this->check_api_rate_limit();
        if ($rate_limit_response) {
            return $rate_limit_response;
        }

        if (!headers_sent()) {
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('Pragma: no-cache');
            header('Expires: 0');
        }

        $hours = max(1, min(720, (int)($request->get_param('hours') ?: 24)));

        $timeseries         = $this->stats->get_timeseries_data($hours);
        $summary            = $this->stats->get_summary_stats();                 // по retention
        $summary_window     = $this->stats->get_summary_stats_window($hours);    // по окну
        $timeseries_blocks  = $this->stats->get_block_timeseries_data($hours);
        $blocks_summary     = $this->stats->get_block_summary($hours);
        $block_reasons      = $this->stats->get_block_reasons_breakdown($hours, 8);
        $score_histogram    = $this->stats->get_score_histogram($hours, 10);
        $ai_ua_list         = $this->stats->get_ai_bot_user_agents($hours);
        $top_factor_hist    = $this->stats->get_top_factor_histogram($hours, 30);

        return new WP_REST_Response([
            'ok'                 => true,
            'timeseries'         => $timeseries,
            'summary'            => $summary,
            'summary_window'     => $summary_window,
            'blocks_summary'     => $blocks_summary,
            'timeseries_blocks'  => $timeseries_blocks,
            'score_histogram'    => $score_histogram,
            'block_reasons'      => $block_reasons,
            'ai_ua'              => $ai_ua_list,
            'hours'              => $hours,
            'generated_at'       => gmdate('c'),
            'top_factor_histogram' => $top_factor_hist,
        ], 200);
    }
}
