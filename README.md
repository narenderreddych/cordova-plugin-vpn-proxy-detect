# cordova-plugin-vpn-proxy-detect

**Purpose:** Detect VPN, Proxy, and basic MITM indications on Android & iOS. Returns a JSON result to JavaScript and supports a single-call API `cordova.plugins.vpnproxy.check(success, error)`.

---

## Features

* Detect active VPN connections (tun0, ppp0, ipsec, utun*, tap*, wg, vti)
* Detect system proxy settings
* Best-effort MITM detection on Android
* Lists active network interfaces
* Retrieves device local IP
* Supports both **Android** and **iOS**
* Optional continuous monitoring via JS
* Works on emulator and real devices

---

## Installation

### From local path

```bash
cordova plugin add <path-to-your-plugin>
```

### From GitHub

```bash
cordova plugin add https://github.com/narenderreddych/cordova-plugin-vpn-proxy-detect.git
```

---

## Usage

### Basic detection

```javascript
document.addEventListener('deviceready', function() {
    cordova.plugins.vpnproxy.check(function(result) {
        console.log('VPN Enabled:', result.vpnEnabled);
        console.log('Proxy Enabled:', result.proxyEnabled);
        console.log('MITM Detected:', result.mitmDetected);
        console.log('Interfaces:', result.interfaces);
        console.log('Local IP:', result.ip);
    }, function(err) {
        console.error('VPN/Proxy check failed:', err);
    });
});
```

### Continuous monitoring (every 10s)

```javascript
var stopMonitor = cordova.plugins.vpnproxy.startMonitor(10000, function(result) {
    console.log('Dynamic check:', result);
    if(result.vpnEnabled || result.proxyEnabled) {
        alert('VPN or Proxy detected!');
    }
});

// Stop monitoring later if needed
// stopMonitor();
```

---

## API Reference

| Method                               | Description                                                                                                 |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------------- |
| `check(success, error)`              | Single detection call; returns object with `vpnEnabled`, `proxyEnabled`, `mitmDetected`, `interfaces`, `ip` |
| `startMonitor(intervalMs, callback)` | Starts periodic detection (interval in ms); returns a stop function                                         |

### Returned Object

```json
{
  "vpnEnabled": true/false,
  "proxyEnabled": true/false,
  "mitmDetected": true/false,
  "interfaces": ["wlan0","tun0"],
  "ip": "10.8.0.2"
}
```

---

## Notes

* **Android:** Checks network interfaces and system proxy properties. MITM detection checks user-added CAs. Some paths may vary depending on Android version.
* **iOS:** Uses `getifaddrs` to detect VPN interfaces (`utun*`, `ipsec`, `ppp`, `tap`). Proxy detection via system proxy settings. MITM detection is limited by OS restrictions.
* **Limitations:**

  * VPN detection depends on OS-level access; some VPNs or split-tunnel setups may evade detection.
  * Proxy detection is best-effort; corporate networks may use complex proxies that are hard to detect.
  * MITM detection is conservative; for critical security, verify SSL certificates server-side.

---

## Testing

* Test on multiple devices with popular VPN apps (OpenVPN, WireGuard, NordVPN).
* Test with corporate proxy setups and mobile carriers.
* Ensure to handle false positives gracefully.

---

## License

MIT
