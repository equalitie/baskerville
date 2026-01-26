/* Baskerville Admin JavaScript */

(function($) {
    'use strict';

    $(document).ready(function() {
        // Initialize Baskerville admin functionality
        console.log('Baskerville admin initialized');

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