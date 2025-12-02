package org.apache.cordova.vpnproxy
val cm = cordova.activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
val networks = cm.allNetworks
for (net in networks) {
val caps = cm.getNetworkCapabilities(net)
if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
return true
}
}
} else {
// Fallback: check active network type (less reliable)
val networkInfo = cm.activeNetworkInfo
if (networkInfo != null && networkInfo.isConnected && networkInfo.typeName.equals("VPN", ignoreCase = true)) {
return true
}
}
// Also check presence of TUN interfaces via /proc/net/dev (best-effort)
try {
val devs = java.io.File("/proc/net/dev").readText()
if (devs.contains("tun") || devs.contains("ppp") || devs.contains("pptp") || devs.contains("tap")) return true
} catch (e: Exception) { /* ignore */ }
return false
}


private fun isProxyEnabled(): Boolean {
// Check system properties (works for many Android devices)
try {
val host = System.getProperty("http.proxyHost") ?: System.getProperty("proxyHost")
val port = System.getProperty("http.proxyPort") ?: System.getProperty("proxyPort")
if (!host.isNullOrEmpty()) return true
} catch (e: Exception) { /* ignore */ }


// On newer Android, use ProxyInfo from ConnectivityManager
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
try {
val cm = cordova.activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
val defaultNetwork = cm.activeNetwork
if (defaultNetwork != null) {
val linkProperties = cm.getLinkProperties(defaultNetwork)
val proxyInfo = linkProperties?.httpProxy
if (proxyInfo != null && proxyInfo.host != null) return true
}
} catch (e: Exception) { /* ignore */ }
}


return false
}


private fun getProxyInfo(): JSONObject? {
try {
val host = System.getProperty("http.proxyHost") ?: System.getProperty("proxyHost")
val portStr = System.getProperty("http.proxyPort") ?: System.getProperty("proxyPort")
if (!host.isNullOrEmpty()) {
val port = try { portStr?.toInt() ?: -1 } catch (e: Exception) { -1 }
val jo = JSONObject()
jo.put("host", host)
jo.put("port", port)
jo.put("type", "system")
return jo
}
} catch (e: Exception) { /* ignore */ }


if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
try {
val cm = cordova.activity.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
val defaultNetwork = cm.activeNetwork
if (defaultNetwork != null) {
val linkProperties = cm.getLinkProperties(defaultNetwork)
val proxyInfo = linkProperties?.httpProxy
if (proxyInfo != null) {
val jo = JSONObject()
jo.put("host", proxyInfo.host ?: JSONObject.NULL)
jo.put("port", proxyInfo.port)
jo.put("exclusionList", proxyInfo.exclusionList?.joinToString(",") ?: JSONObject.NULL)
jo.put("type", "linkProperties")
return jo
}
}
} catch (e: Exception) { /* ignore */ }
}


return null
}
}
