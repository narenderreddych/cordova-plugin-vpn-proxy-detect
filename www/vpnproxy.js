var exec = require('cordova/exec');


exports.check = function(success, error) {
exec(function(result) {
success(result);
}, function(err) {
error(err);
}, 'VpnProxyDetect', 'check', []);
};


// Optional convenience: poll method
exports.startMonitor = function(intervalMs, onResult) {
intervalMs = intervalMs || 10000; // default 10s
var timer = setInterval(function() {
exports.check(function(r) { if (onResult) onResult(r); }, function(e) { console.error('vpnDetect error', e); });
}, intervalMs);
return function stop() { clearInterval(timer); };
};
