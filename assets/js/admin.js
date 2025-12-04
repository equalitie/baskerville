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

            $btn.prop('disabled', true).text('Importing...');
            $result.html('<span class="spinner is-active" style="float:none;margin:0;"></span>');

            $.ajax({
                url: ajaxurl,
                type: 'POST',
                data: {
                    action: 'baskerville_import_logs',
                    nonce: baskervilleAdmin.importLogsNonce
                },
                success: function(response) {
                    if (response.success) {
                        $result.html('<span style="color: #46b450;">✓ ' + response.data.message + '</span>');
                        // Reload page after 2 seconds to update stats
                        setTimeout(function() {
                            location.reload();
                        }, 2000);
                    } else {
                        $result.html('<span style="color: #dc3232;">✗ ' + (response.data.message || 'Import failed') + '</span>');
                        $btn.prop('disabled', false).text('Import Logs Now');
                    }
                },
                error: function() {
                    $result.html('<span style="color: #dc3232;">✗ AJAX error occurred</span>');
                    $btn.prop('disabled', false).text('Import Logs Now');
                }
            });
        });
    });

})(jQuery);