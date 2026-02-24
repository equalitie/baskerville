/* Baskerville Admin JavaScript */

(function($) {
    'use strict';

    $(document).ready(function() {
        // Initialize Baskerville admin functionality
        console.log('Baskerville admin initialized');

        // GeoIP mode field toggling and Select2 init
        if ($('.baskerville-geoip-mode-radio').length) {
            $('.baskerville-country-select').select2({
                placeholder: baskervilleAdmin.i18n.searchCountries,
                allowClear: true,
                width: '100%'
            });

            function updateGeoIPFields() {
                var selectedMode = $('input[name="baskerville_settings[geoip_mode]"]:checked').val();
                var $blacklistField = $('#baskerville_blacklist_countries');
                var $whitelistField = $('#baskerville_whitelist_countries');
                var $blacklistContainer = $blacklistField.closest('div');
                var $whitelistContainer = $whitelistField.closest('div');

                $blacklistField.prop('disabled', true);
                $whitelistField.prop('disabled', true);
                $blacklistContainer.css('opacity', '0.5');
                $whitelistContainer.css('opacity', '0.5');

                if (selectedMode === 'blacklist') {
                    $blacklistField.prop('disabled', false);
                    $blacklistContainer.css('opacity', '1');
                } else if (selectedMode === 'whitelist') {
                    $whitelistField.prop('disabled', false);
                    $whitelistContainer.css('opacity', '1');
                }
            }

            $('.baskerville-geoip-mode-radio').on('change', updateGeoIPFields);
            updateGeoIPFields();
        }

        // AI Bot blocking mode field toggling
        if ($('.baskerville-aibot-mode-radio').length) {
            function updateAIBotFields() {
                var selectedMode = $('input[name="baskerville_settings[ai_bot_blocking_mode]"]:checked').val();
                var $blacklistField = $('#baskerville_blacklist_ai_companies');
                var $whitelistField = $('#baskerville_whitelist_ai_companies');
                var $blacklistContainer = $blacklistField.closest('div');
                var $whitelistContainer = $whitelistField.closest('div');

                $blacklistField.prop('disabled', true);
                $whitelistField.prop('disabled', true);
                $blacklistContainer.css('opacity', '0.5');
                $whitelistContainer.css('opacity', '0.5');

                if (selectedMode === 'blacklist') {
                    $blacklistField.prop('disabled', false);
                    $blacklistContainer.css('opacity', '1');
                } else if (selectedMode === 'whitelist') {
                    $whitelistField.prop('disabled', false);
                    $whitelistContainer.css('opacity', '1');
                }
            }

            $('.baskerville-aibot-mode-radio').on('change', updateAIBotFields);
            updateAIBotFields();
        }

        // AI Bot company Select2 init
        if ($('.baskerville-aibot-select').length) {
            $('.baskerville-aibot-select').select2({
                placeholder: baskervilleAdmin.i18n.searchCompanies,
                allowClear: true,
                width: '100%'
            });
        }

        // Country statistics charts (Chart.js)
        if (window.baskervilleCountryData && document.getElementById('baskervilleCountryTrafficChart')) {
            (function waitForChart() {
                if (typeof Chart === 'undefined') {
                    setTimeout(waitForChart, 100);
                    return;
                }

                var countryStats = window.baskervilleCountryData;
                var hours = window.baskervilleCountryHours;
                var i18n = baskervilleAdmin.i18n;

                var topCountries = countryStats.slice(0, 15);
                var labels = topCountries.map(function(c) { return c.name + ' (' + c.code + ')'; });
                var totalData = topCountries.map(function(c) { return c.total; });
                var blockedData = topCountries.map(function(c) { return c.blocked; });

                var colors = [
                    '#4CAF50', '#2196F3', '#FF9800', '#9C27B0', '#F44336',
                    '#00BCD4', '#FFEB3B', '#795548', '#607D8B', '#E91E63',
                    '#3F51B5', '#8BC34A', '#FF5722', '#009688', '#FFC107'
                ];

                // Total Traffic by Country
                new Chart(document.getElementById('baskervilleCountryTrafficChart').getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: i18n.totalRequests,
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
                                text: i18n.trafficByCountryLast + ' ' + hours + 'h',
                                font: { size: 16, weight: 'bold' }
                            },
                            legend: { display: false }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                title: { display: true, text: i18n.requests }
                            }
                        }
                    }
                });

                // 403 Bans by Country
                new Chart(document.getElementById('baskervilleCountryBansChart').getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: i18n.banned403,
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
                                text: i18n.bansByCountryLast + ' ' + hours + 'h',
                                font: { size: 16, weight: 'bold' }
                            },
                            legend: { display: false }
                        },
                        scales: {
                            x: {
                                beginAtZero: true,
                                title: { display: true, text: i18n.blockedRequests }
                            }
                        }
                    }
                });
            })();
        }

        // AI Bots Chart (Chart.js)
        if (window.baskervilleAIBotData && document.getElementById('aiBotsChart')) {
            (function waitForChart() {
                if (typeof Chart === 'undefined') {
                    setTimeout(waitForChart, 100);
                    return;
                }

                var data = window.baskervilleAIBotData;
                var i18n = baskervilleAdmin.i18n;

                // Prepare labels (time slots)
                var labels = data.time_slots.map(function(slot) {
                    var date = new Date(slot.replace(' ', 'T') + 'Z');
                    var hours = String(date.getUTCHours()).padStart(2, '0');
                    var minutes = String(date.getUTCMinutes()).padStart(2, '0');
                    return hours + ':' + minutes;
                });

                // Company colors
                var companyColors = {
                    'OpenAI': '#10a37f',
                    'Anthropic': '#d4a574',
                    'Google': '#4285f4',
                    'Meta': '#0668e1',
                    'ByteDance': '#fe2c55',
                    'Amazon': '#ff9900',
                    'Baidu': '#2932e1',
                    'Perplexity': '#6366f1',
                    'Cohere': '#7c3aed',
                    'Common Crawl': '#9ca3af',
                    'Huawei': '#e91e63',
                    'Unknown': '#6b7280',
                    'Generic': '#9ca3af'
                };

                // Prepare datasets
                var datasets = [];
                Object.keys(data.companies).forEach(function(company) {
                    datasets.push({
                        label: company,
                        data: data.companies[company],
                        backgroundColor: companyColors[company] || '#9ca3af',
                        borderColor: companyColors[company] || '#9ca3af',
                        borderWidth: 1
                    });
                });

                // Create chart
                var ctx = document.getElementById('aiBotsChart').getContext('2d');
                new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: datasets
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        interaction: {
                            mode: 'index',
                            intersect: false
                        },
                        scales: {
                            x: {
                                stacked: true,
                                title: {
                                    display: true,
                                    text: i18n.timeUtc
                                },
                                ticks: {
                                    maxRotation: 45,
                                    minRotation: 45
                                }
                            },
                            y: {
                                stacked: true,
                                beginAtZero: true,
                                title: {
                                    display: true,
                                    text: i18n.hits
                                }
                            }
                        },
                        plugins: {
                            title: {
                                display: true,
                                text: i18n.aiBotHitsLast + ' ' + data.hours + 'h',
                                font: {
                                    size: 16,
                                    weight: 'bold'
                                }
                            },
                            legend: {
                                display: true,
                                position: 'bottom'
                            },
                            tooltip: {
                                callbacks: {
                                    footer: function(items) {
                                        var total = 0;
                                        items.forEach(function(item) {
                                            total += item.parsed.y;
                                        });
                                        return 'Total: ' + total;
                                    }
                                }
                            }
                        }
                    }
                });
            })();
        }

        // Install MaxMind Library button handler
        $('#baskerville-install-maxmind').on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var $status = $('#baskerville-install-status');
            var i18n = baskervilleAdmin.i18n;

            $btn.prop('disabled', true).text(i18n.installing);
            $status.html('<span class="baskerville-status-pending">' + i18n.downloadingLib + '</span>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_install_maxmind',
                    nonce: baskervilleAdmin.installMaxmindNonce
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<span class="baskerville-status-success">' + response.data.message + '</span>');
                        setTimeout(function() {
                            location.reload();
                        }, 2000);
                    } else {
                        var errorMsg = response.data.message || 'Installation failed';
                        var errorHtml = '<span class="baskerville-status-error">' + errorMsg + '</span>';

                        if (response.data.errors && response.data.errors.length > 0) {
                            errorHtml += '<br><small class="baskerville-status-error-detail">Details: ' + response.data.errors.join(', ') + '</small>';
                        }

                        $status.html(errorHtml);
                        $btn.prop('disabled', false).text(i18n.retryInstall);
                    }
                },
                error: function() {
                    $status.html('<span class="baskerville-status-error">' + i18n.installFailed + '</span>');
                    $btn.prop('disabled', false).text(i18n.installMaxmind);
                }
            });
        });

        // Update Deflect GeoIP button handler
        $('#baskerville-update-deflect-geoip').on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var $status = $('#baskerville-deflect-status');
            var i18n = baskervilleAdmin.i18n;

            $btn.prop('disabled', true).text(i18n.downloading);
            $status.html('<span class="baskerville-status-pending">' + i18n.checkingUpdates + '</span>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_update_deflect_geoip',
                    nonce: baskervilleAdmin.updateDeflectNonce,
                    force: 'true'
                },
                success: function(response) {
                    if (response.success) {
                        var msg = response.data.message;
                        if (response.data.stats) {
                            msg += ' (IPv4: ' + response.data.stats.ipv4_count + ', IPv6: ' + response.data.stats.ipv6_count + ')';
                        }
                        $status.html('<span class="baskerville-status-success">' + msg + '</span>');
                        if (response.data.updated) {
                            setTimeout(function() {
                                location.reload();
                            }, 2000);
                        } else {
                            $btn.prop('disabled', false).text(i18n.checkForUpdates);
                        }
                    } else {
                        $status.html('<span class="baskerville-status-error">' + response.data.message + '</span>');
                        $btn.prop('disabled', false).text(i18n.retry);
                    }
                },
                error: function() {
                    $status.html('<span class="baskerville-status-error">' + i18n.requestFailed + '</span>');
                    $btn.prop('disabled', false).text(i18n.retry);
                }
            });
        });

        // Clear GeoIP Cache button handler
        $('#baskerville-clear-geoip-cache').on('click', function(e) {
            e.preventDefault();
            var $btn = $(this);
            var $status = $('#baskerville-clear-cache-status');
            var i18n = baskervilleAdmin.i18n;

            $btn.prop('disabled', true).text(i18n.clearing);
            $status.html('<span class="baskerville-status-pending">' + i18n.clearingCache + '</span>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_clear_geoip_cache',
                    nonce: baskervilleAdmin.clearGeoipCacheNonce
                },
                success: function(response) {
                    if (response.success) {
                        $status.html('<span class="baskerville-status-success">' + response.data.message + '</span>');
                        $btn.text(i18n.clearGeoipCache);
                        setTimeout(function() {
                            location.reload();
                        }, 1500);
                    } else {
                        var errorMsg = response.data.message || 'Failed to clear cache';
                        $status.html('<span class="baskerville-status-error">' + errorMsg + '</span>');
                        $btn.prop('disabled', false).text(i18n.clearGeoipCache);
                    }
                },
                error: function() {
                    $status.html('<span class="baskerville-status-error">' + i18n.clearCacheFailed + '</span>');
                    $btn.prop('disabled', false).text(i18n.clearGeoipCache);
                }
            });
        });

        // Analytics Charts (Chart.js)
        if (window.baskervilleAnalyticsData && document.getElementById('baskervilleHumAutoBar')) {
            (function waitForChart() {
                if (typeof Chart === 'undefined') {
                    setTimeout(waitForChart, 100);
                    return;
                }

                var timeseries = window.baskervilleAnalyticsData.timeseries;
                var turnstileData = window.baskervilleAnalyticsData.turnstile;
                var hours = window.baskervilleAnalyticsData.hours;
                var i18n = baskervilleAdmin.i18n;

                if (!timeseries || timeseries.length === 0) {
                    document.getElementById('baskervilleHumAutoBar').parentElement.innerHTML = '<p class="baskerville-no-data">' + i18n.noDataPeriod + '</p>';
                    document.getElementById('baskervilleHumAutoPie').parentElement.innerHTML = '<p class="baskerville-no-data">' + i18n.noDataAvailable + '</p>';
                    return;
                }

                function fmtHHMM(timeStr) {
                    var d = new Date(timeStr + 'Z');
                    var hh = String(d.getHours()).padStart(2, '0');
                    var mm = String(d.getMinutes()).padStart(2, '0');
                    return hh + ':' + mm;
                }

                var labels = timeseries.map(function(i) { return fmtHHMM(i.time); });
                var humans = timeseries.map(function(i) { return i.human_count || 0; });
                var automated = timeseries.map(function(i) {
                    return (i.bad_bot_count||0) + (i.ai_bot_count||0) + (i.bot_count||0) + (i.verified_bot_count||0);
                });

                var totalHumans = humans.reduce(function(a,b) { return a+b; }, 0);
                var totalAutomated = automated.reduce(function(a,b) { return a+b; }, 0);

                // 1) Stacked Bar: Humans vs Automated
                new Chart(document.getElementById('baskervilleHumAutoBar').getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            { label: i18n.humans, data: humans, stack: 'visits', backgroundColor: '#4CAF50' },
                            { label: i18n.automated, data: automated, stack: 'visits', backgroundColor: '#FF9800' }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: true,
                        interaction: { mode: 'index', intersect: false },
                        scales: {
                            x: { stacked: true, title: { display: true, text: i18n.time } },
                            y: { stacked: true, beginAtZero: true, title: { display: true, text: i18n.visits } }
                        },
                        plugins: {
                            title: { display: true, text: i18n.humansVsAutoLast + ' ' + hours + 'h' },
                            tooltip: {
                                callbacks: {
                                    afterBody: function(items) {
                                        var idx = items[0].dataIndex;
                                        var total = (humans[idx]||0) + (automated[idx]||0);
                                        var hp = total ? Math.round((humans[idx]*100)/total) : 0;
                                        var ap = total ? Math.round((automated[idx]*100)/total) : 0;
                                        return [i18n.total + ' ' + total, i18n.humansLabel + ' ' + humans[idx] + ' (' + hp + '%)', i18n.automatedLabel + ' ' + automated[idx] + ' (' + ap + '%)'];
                                    }
                                }
                            }
                        }
                    }
                });

                // 2) Pie: Humans vs Automated
                new Chart(document.getElementById('baskervilleHumAutoPie').getContext('2d'), {
                    type: 'pie',
                    data: {
                        labels: [i18n.humans, i18n.automated],
                        datasets: [{ data: [totalHumans, totalAutomated], backgroundColor: ['#4CAF50', '#FF9800'] }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: true,
                        plugins: {
                            title: { display: true, text: i18n.trafficDistLast + ' ' + hours + 'h' },
                            legend: { position: 'bottom' },
                            tooltip: {
                                callbacks: {
                                    label: function(ctx) {
                                        var v = ctx.parsed || 0;
                                        var sum = totalHumans + totalAutomated || 1;
                                        var pct = Math.round((v*100)/sum);
                                        return ' ' + ctx.label + ': ' + v + ' (' + pct + '%)';
                                    }
                                }
                            }
                        }
                    }
                });

                // Bot types data
                var badBots = timeseries.map(function(i) { return i.bad_bot_count || 0; });
                var aiBots = timeseries.map(function(i) { return i.ai_bot_count || 0; });
                var bots = timeseries.map(function(i) { return i.bot_count || 0; });
                var verifiedBots = timeseries.map(function(i) { return i.verified_bot_count || 0; });

                var totalBadBots = badBots.reduce(function(a,b) { return a+b; }, 0);
                var totalAiBots = aiBots.reduce(function(a,b) { return a+b; }, 0);
                var totalBots = bots.reduce(function(a,b) { return a+b; }, 0);
                var totalVerifiedBots = verifiedBots.reduce(function(a,b) { return a+b; }, 0);

                // 3) Stacked Bar: Bot Types
                new Chart(document.getElementById('baskervilleBotTypesBar').getContext('2d'), {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [
                            { label: i18n.badBots, data: badBots, stack: 'bots', backgroundColor: '#F44336' },
                            { label: i18n.aiBots, data: aiBots, stack: 'bots', backgroundColor: '#9C27B0' },
                            { label: i18n.otherBots, data: bots, stack: 'bots', backgroundColor: '#FF9800' },
                            { label: i18n.verifiedCrawlers, data: verifiedBots, stack: 'bots', backgroundColor: '#2196F3' }
                        ]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: true,
                        interaction: { mode: 'index', intersect: false },
                        scales: {
                            x: { stacked: true, title: { display: true, text: i18n.time } },
                            y: { stacked: true, beginAtZero: true, title: { display: true, text: i18n.count } }
                        },
                        plugins: {
                            title: { display: true, text: i18n.botTypesLast + ' ' + hours + 'h' },
                            tooltip: {
                                callbacks: {
                                    afterBody: function(items) {
                                        var idx = items[0].dataIndex;
                                        var total = (badBots[idx]||0) + (aiBots[idx]||0) + (bots[idx]||0) + (verifiedBots[idx]||0);
                                        return [i18n.totalBots + ' ' + total];
                                    }
                                }
                            }
                        }
                    }
                });

                // 4) Pie: Bot Types Distribution
                new Chart(document.getElementById('baskervilleBotTypesPie').getContext('2d'), {
                    type: 'pie',
                    data: {
                        labels: [i18n.badBots, i18n.aiBots, i18n.otherBots, i18n.verifiedCrawlers],
                        datasets: [{ data: [totalBadBots, totalAiBots, totalBots, totalVerifiedBots], backgroundColor: ['#F44336', '#9C27B0', '#FF9800', '#2196F3'] }]
                    },
                    options: {
                        responsive: true, maintainAspectRatio: true,
                        plugins: {
                            title: { display: true, text: i18n.botTypesDistLast + ' ' + hours + 'h' },
                            legend: { position: 'bottom' },
                            tooltip: {
                                callbacks: {
                                    label: function(ctx) {
                                        var v = ctx.parsed || 0;
                                        var sum = totalBadBots + totalAiBots + totalBots + totalVerifiedBots || 1;
                                        var pct = Math.round((v*100)/sum);
                                        return ' ' + ctx.label + ': ' + v + ' (' + pct + '%)';
                                    }
                                }
                            }
                        }
                    }
                });

                // 5) Turnstile Precision Chart
                if (turnstileData && turnstileData.timeseries && turnstileData.timeseries.length > 0) {
                    var tsTimeseries = turnstileData.timeseries;
                    var tsLabels = tsTimeseries.map(function(i) { return fmtHHMM(i.time); });
                    var tsRedirects = tsTimeseries.map(function(i) { return i.redirect_count || 0; });
                    var tsPasses = tsTimeseries.map(function(i) { return i.pass_count || 0; });
                    var tsFails = tsTimeseries.map(function(i) { return Math.max(0, (i.redirect_count || 0) - (i.pass_count || 0)); });

                    new Chart(document.getElementById('baskervilleTurnstileBar').getContext('2d'), {
                        type: 'bar',
                        data: {
                            labels: tsLabels,
                            datasets: [
                                { label: i18n.passedHumans, data: tsPasses, stack: 'challenges', backgroundColor: '#4CAF50' },
                                { label: i18n.failedBots, data: tsFails, stack: 'challenges', backgroundColor: '#E91E63' }
                            ]
                        },
                        options: {
                            responsive: true, maintainAspectRatio: true,
                            interaction: { mode: 'index', intersect: false },
                            scales: {
                                x: { stacked: true, title: { display: true, text: i18n.time } },
                                y: { stacked: true, beginAtZero: true, title: { display: true, text: i18n.challenges } }
                            },
                            plugins: {
                                title: { display: true, text: i18n.turnstileChallenges + ' — last ' + hours + 'h' },
                                tooltip: {
                                    callbacks: {
                                        afterBody: function(items) {
                                            var idx = items[0].dataIndex;
                                            var redirects = tsRedirects[idx] || 0;
                                            var passes = tsPasses[idx] || 0;
                                            var precision = redirects > 0 ? Math.round(((redirects - passes) * 100) / redirects) : 0;
                                            return [i18n.redirects + ' ' + redirects, i18n.precision + ' ' + precision + '%'];
                                        }
                                    }
                                }
                            }
                        }
                    });

                    document.getElementById('turnstilePrecisionValue').textContent = turnstileData.total_precision + '%';

                    var totalFailed = Math.max(0, turnstileData.total_redirects - turnstileData.total_passes);
                    document.getElementById('turnstileStats').innerHTML =
                        '<strong>' + i18n.challenged + '</strong> ' + turnstileData.total_redirects + '<br>' +
                        '<strong>' + i18n.passed + '</strong> ' + turnstileData.total_passes + '<br>' +
                        '<strong>' + i18n.failed + '</strong> ' + totalFailed;
                } else {
                    document.getElementById('baskervilleTurnstileBar').parentElement.innerHTML = '<p class="baskerville-no-data">' + i18n.noTurnstileData + '</p>';
                    document.getElementById('turnstilePrecisionValue').textContent = '—';
                    document.getElementById('turnstileStats').innerHTML = '<em>' + i18n.noChallengesRecorded + '</em>';
                }
            })();
        }

        // IP Lookup handler
        $('#baskerville-ip-lookup-btn').on('click', function() {
            var ip = $('#baskerville-ip-lookup').val().trim();
            var i18n = baskervilleAdmin.i18n;
            if (!ip) {
                alert(i18n.enterIpAddress);
                return;
            }

            var $btn = $(this);
            var $results = $('#baskerville-ip-results');

            $btn.prop('disabled', true).text(i18n.searching);
            $results.html('<p class="baskerville-loading"><span class="dashicons dashicons-update baskerville-spinner"></span> ' + i18n.loading + '</p>').show();

            function getClassColor(classification) {
                var colors = {
                    'bad_bot': '#f44336', 'ai_bot': '#9c27b0', 'bot': '#ff9800',
                    'verified_bot': '#2196f3', 'human': '#4caf50', 'unknown': '#9e9e9e'
                };
                return colors[classification] || '#9e9e9e';
            }

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_ip_lookup',
                    ip: ip,
                    _wpnonce: baskervilleAdmin.ipLookupNonce
                },
                success: function(response) {
                    $btn.prop('disabled', false).text(i18n.search);

                    if (response.success) {
                        var data = response.data;
                        var html = '';

                        html += '<div class="baskerville-ip-result-box ' + (data.is_banned ? 'banned' : 'allowed') + '">';
                        html += '<h3>' + (data.is_banned ? '\uD83D\uDEAB' : '\u2705') + ' ' + i18n.ipLabel + ' ' + $('<div>').text(ip).html() + '</h3>';
                        html += '<p><strong>' + i18n.statusLabel + '</strong> ' + (data.is_banned ? i18n.currentlyBanned : i18n.notBanned) + '</p>';
                        if (data.country) {
                            html += '<p><strong>' + i18n.countryLabel + '</strong> ' + $('<div>').text(data.country).html() + '</p>';
                        }
                        if (data.total_events > 0) {
                            html += '<p><strong>' + i18n.totalEvents + '</strong> ' + data.total_events + '</p>';
                            html += '<p><strong>' + i18n.blockEvents + '</strong> ' + data.block_events + '</p>';
                        }
                        html += '</div>';

                        if (data.events && data.events.length > 0) {
                            html += '<h3>' + i18n.recentEvents + '</h3>';
                            html += '<div class="baskerville-events-scroll">';
                            html += '<table class="baskerville-events-table">';
                            html += '<thead><tr>';
                            html += '<th>' + i18n.timeHeader + '</th>';
                            html += '<th>' + i18n.classification + '</th>';
                            html += '<th>' + i18n.scoreHeader + '</th>';
                            html += '<th>' + i18n.blockReasonHeader + '</th>';
                            html += '<th>' + i18n.userAgentHeader + '</th>';
                            html += '</tr></thead><tbody>';

                            data.events.forEach(function(event) {
                                var hasBlock = event.block_reason && event.block_reason !== '';
                                var rowClass = hasBlock ? 'class="baskerville-row-blocked"' : '';
                                html += '<tr ' + rowClass + '>';
                                html += '<td class="baskerville-nowrap">' + $('<div>').text(event.timestamp).html() + '</td>';
                                html += '<td><span class="baskerville-badge" style="background: ' + getClassColor(event.classification) + ';">' + $('<div>').text(event.classification || 'unknown').html() + '</span></td>';
                                html += '<td class="baskerville-score-cell ' + (event.score >= 50 ? 'high' : 'low') + '">' + (event.score || 0) + '</td>';
                                html += '<td class="' + (hasBlock ? 'baskerville-block-reason' : 'baskerville-text-muted') + '">' + $('<div>').text(event.block_reason || '-').html() + '</td>';
                                html += '<td class="ua-cell" title="' + $('<div>').text(event.user_agent || '').html() + '">' + $('<div>').text((event.user_agent || '').substring(0, 50) + (event.user_agent && event.user_agent.length > 50 ? '...' : '')).html() + '</td>';
                                html += '</tr>';
                            });

                            html += '</tbody></table></div>';
                        } else {
                            html += '<p class="baskerville-text-muted baskerville-italic">' + i18n.noEventsFound + '</p>';
                        }

                        $results.html(html);
                    } else {
                        $results.html('<div class="notice notice-error"><p>' + (response.data || i18n.errorSearchingIp) + '</p></div>');
                    }
                },
                error: function() {
                    $btn.prop('disabled', false).text(i18n.search);
                    $results.html('<div class="notice notice-error"><p>' + i18n.requestFailed + '</p></div>');
                }
            });
        });

        // Allow Enter key to trigger IP search
        $('#baskerville-ip-lookup').on('keypress', function(e) {
            if (e.which === 13) {
                $('#baskerville-ip-lookup-btn').click();
            }
        });

        // Benchmark button handler
        $('.benchmark-btn').on('click', function() {
            var $btn = $(this);
            var test = $btn.data('test');
            var $result = $('.benchmark-result[data-test="' + test + '"]');
            var i18n = baskervilleAdmin.i18n;

            $btn.prop('disabled', true);
            $result.removeClass('success error').addClass('loading').text(i18n.running);

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_run_benchmark',
                    nonce: baskervilleAdmin.benchmarkNonce,
                    test: test
                },
                success: function(response) {
                    if (response.success) {
                        $result.removeClass('loading').addClass('success').html(response.data.message);
                    } else {
                        $result.removeClass('loading').addClass('error').text(response.data.message || i18n.benchmarkError);
                    }
                },
                error: function() {
                    $result.removeClass('loading').addClass('error').text(i18n.benchmarkAjaxError);
                },
                complete: function() {
                    $btn.prop('disabled', false);
                }
            });
        });

        // Import logs button handler
        $('#import-logs-now').on('click', function() {
            var $btn = $(this);
            var $result = $('#import-logs-result');

            $btn.prop('disabled', true).text(baskervilleAdmin.i18n.importing);
            $result.html('<span class="spinner is-active baskerville-spinner-inline"></span>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_import_logs',
                    nonce: baskervilleAdmin.importLogsNonce
                },
                success: function(response) {
                    if (response.success) {
                        $result.html('<span class="baskerville-status-success">✓ ' + response.data.message + '</span>');
                        // Reload page after 2 seconds to update stats
                        setTimeout(function() {
                            location.reload();
                        }, 2000);
                    } else {
                        $result.html('<span class="baskerville-status-error">✗ ' + (response.data.message || baskervilleAdmin.i18n.importFailed) + '</span>');
                        $btn.prop('disabled', false).text(baskervilleAdmin.i18n.importLogsNow);
                    }
                },
                error: function() {
                    $result.html('<span class="baskerville-status-error">✗ ' + baskervilleAdmin.i18n.ajaxError + '</span>');
                    $btn.prop('disabled', false).text(baskervilleAdmin.i18n.importLogsNow);
                }
            });
        });
    });

})(jQuery);