A Cordova plugin to detect VPN and Proxy status on Android (API 26+) and iOS (iOS 15+). Includes methods:

- `isVpnConnected()` -> Promise<boolean>
- `isProxyEnabled()` -> Promise<boolean>
- `getProxyInfo()` -> Promise<object|null> (host, port, type)

## README.md (usage snippet)


```md
# cordova-plugin-vpn-proxy-detect


## Install


From local folder:


```bash
cordova plugin add /path/to/cordova-plugin-vpn-proxy-detect
```


Or from npm (if published):


```bash
cordova plugin add cordova-plugin-vpn-proxy-detect
```


## Usage


```js
cordova.plugins.vpnproxy.isVpnConnected().then(function(connected){
console.log('VPN connected?', connected);
});


cordova.plugins.vpnproxy.isProxyEnabled().then(function(enabled){
console.log('Proxy enabled?', enabled);
});


cordova.plugins.vpnproxy.getProxyInfo().then(function(info){
console.log('Proxy info', info);
}).catch(function(){
console.log('No proxy');
});
```


## Platform support & notes


- Android: targeted for Android 8 (API 26) and above. VPN detection uses `NetworkCapabilities.TRANSPORT_VPN` and best-effort `/proc/net/dev` checks for older devices.
- iOS: targeted for iOS 15 and above. Uses `getifaddrs` to detect VPN interfaces and CFNetwork API for proxy detection.


## Limitations


- VPN detection cannot differentiate between user-configured VPNs and app VPNs in all cases.
- iOS NEVPNManager requires special entitlements if you want to list/profile VPN configurations — this plugin avoids that by scanning network interfaces.
- Proxy detection reads system proxy settings; some managed device policies or custom VPNs may obfuscate detection.


## Future improvements


- Add Swift/Obj-C bridge improvements and Objective-C fallback.
- Add richer Android proxy detection using `ProxyInfo` and per-network inspections for older API levels.
- Add unit tests and CI for building the plugin for Cordova CLI and Capacitor.
