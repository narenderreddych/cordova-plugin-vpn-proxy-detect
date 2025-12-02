var exec = require('cordova/exec');

var PLUGIN_NAME = 'VpnProxyDetect';

module.exports = {
isVpnConnected: function () {
return new Promise(function (resolve, reject) {
exec(resolve, reject, PLUGIN_NAME, 'isVpnConnected', []);
});
},


isProxyEnabled: function () {
return new Promise(function (resolve, reject) {
exec(resolve, reject, PLUGIN_NAME, 'isProxyEnabled', []);
});
},


getProxyInfo: function () {
return new Promise(function (resolve, reject) {
exec(resolve, reject, PLUGIN_NAME, 'getProxyInfo', []);
});
}
};
