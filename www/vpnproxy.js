var exec = require('cordova/exec');

exports.check = function(success, error) {
    exec(
        function(result) {
            // Parse result if it's a string
            var parsedResult = typeof result === 'string' ? JSON.parse(result) : result;
            if (success && typeof success === 'function') {
                success(parsedResult);
            }
        }, 
        function(err) {
            console.error('[VPNProxy] Plugin error:', err);
            if (error && typeof error === 'function') {
                error(err);
            }
        }, 
        'VpnProxyDetect', 
        'check', 
        []
    );
};

exports.startMonitor = function(intervalMs, onResult) {
    intervalMs = intervalMs || 10000;
    var isRunning = true;
    
    var timer = setInterval(function() {
        if (!isRunning) return;
        
        exports.check(
            function(r) { 
                if (onResult && typeof onResult === 'function') {
                    onResult(r); 
                }
            }, 
            function(e) { 
                console.error('[VPNProxy] Monitoring error:', e); 
            }
        );
    }, intervalMs);
    
    return function stop() { 
        isRunning = false;
        clearInterval(timer); 
        console.log('[VPNProxy] Monitoring stopped');
    };
};
