# cordova-plugin-vpn-proxy-detect

**Cordova plugin to detect VPN and Proxy on Android and iOS**

## Features

* Detect active VPN connections (tun0, ppp0, ipsec, utun*, tap*, wg, vti)
* Detect system proxy settings (HTTP/HTTPS)
* Basic MITM detection (local proxies)
* List active network interfaces
* Get device local IP address
* Supports both Android and iOS
* Continuous monitoring option
* Works on emulator and real devices

## Installation

### From GitHub

```bash
cordova plugin add https://github.com/narenderreddych/cordova-plugin-vpn-proxy-detect.git

## **Usage**

document.addEventListener('deviceready', function() {
    cordova.plugins.vpnproxy.check(function(result) {
        console.log('VPN Enabled:', result.vpnEnabled);
        console.log('Proxy Enabled:', result.proxyEnabled);
        console.log('MITM Detected:', result.mitmDetected);
        console.log('Interfaces:', result.interfaces);
        console.log('Local IP:', result.ip);
    }, function(err) {
        console.error('Check failed:', err);
    });
});

## Continuous monitoring 
var stopMonitor = cordova.plugins.vpnproxy.startMonitor(10000, function(result) {
    console.log('Update:', result);
    if(result.vpnEnabled || result.proxyEnabled) {
        alert('VPN or Proxy detected!');
    }
});

// Stop monitoring when needed
// stopMonitor();
