import Foundation
let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: proxy)
self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
}


@objc(getProxyInfo:)
func getProxyInfo(command: CDVInvokedUrlCommand) {
if let info = VpnProxyDetector.getProxyInfo() {
let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: info)
self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
} else {
let pluginResult = CDVPluginResult(status: CDVCommandStatus_OK, messageAs: NSNull())
self.commandDelegate.send(pluginResult, callbackId: command.callbackId)
}
}


// MARK: - Helpers
static func isVPNConnected() -> Bool {
// Check for utun interfaces
var ifaddrPtr: UnsafeMutablePointer<ifaddrs>? = nil
guard getifaddrs(&ifaddrPtr) == 0, let firstAddr = ifaddrPtr else { return false }
var ptr = firstAddr
var found = false
while ptr.pointee.ifa_next != nil {
let name = String(cString: ptr.pointee.ifa_name)
if name.hasPrefix("utun") || name.hasPrefix("ppp") || name.hasPrefix("tun") {
found = true
break
}
ptr = ptr.pointee.ifa_next.pointee
}
freeifaddrs(ifaddrPtr)
return found
}


static func isProxyEnabled() -> Bool {
if let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
if let httpEnable = settings[kCFNetworkProxiesHTTPEnable as String] as? Int, httpEnable == 1 { return true }
if let httpsEnable = settings[kCFNetworkProxiesHTTPSEnable as String] as? Int, httpsEnable == 1 { return true }
if let autoConfigEnable = settings[kCFNetworkProxiesProxyAutoConfigEnable as String] as? Int, autoConfigEnable == 1 { return true }
}
return false
}


static func getProxyInfo() -> [String: Any]? {
if let settings = CFNetworkCopySystemProxySettings()?.takeRetainedValue() as? [String: Any] {
var out: [String: Any] = [:]
if let host = settings[kCFNetworkProxiesHTTPProxy as String] as? String {
out["host"] = host
}
if let port = settings[kCFNetworkProxiesHTTPPort as String] as? Int {
out["port"] = port
}
if let proxyAutoConfigURL = settings[kCFNetworkProxiesProxyAutoConfigURLString as String] as? String {
out["pac"] = proxyAutoConfigURL
}
if out.count > 0 { return out }
}
return nil
}
}
