A Cordova plugin to detect VPN and Proxy status on Android (API 26+) and iOS (iOS 15+). Includes methods:


- `isVpnConnected()` -> Promise<boolean>
- `isProxyEnabled()` -> Promise<boolean>
- `getProxyInfo()` -> Promise<object|null> (host, port, type)
