package com.vpndetect;
}
} catch (Exception e) {
Log.e(TAG, "isVpnActive error", e);
}
return false;
}


private List<String> getInterfaceNames() {
List<String> names = new ArrayList<String>();
try {
Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
for (NetworkInterface intf : Collections.list(interfaces)) {
names.add(intf.getName());
}
} catch (Exception e) { }
return names;
}


private boolean isProxyActive() {
try {
String proxyHost = System.getProperty("http.proxyHost");
String proxyPort = System.getProperty("http.proxyPort");
if (proxyHost != null && proxyHost.length() > 0) return true;
if (proxyPort != null && proxyPort.length() > 0) return true;


// For Android API >= 14
if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
ConnectivityManager cm = (ConnectivityManager) cordova.getActivity().getSystemService(Context.CONNECTIVITY_SERVICE);
NetworkInfo info = cm.getActiveNetworkInfo();
if (info != null && info.isConnected()) {
// no direct indicator here; rely on system properties above
}
}
} catch (Exception e) { }
return false;
}


private boolean isMitmPresent() {
// Best-effort: check for user-added CAs on Android (requires file access privileges)
// This method attempts to list files in the user-added certs folder (Android). On some devices path may vary or be restricted.
try {
if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.N) {
// From Android N, user-added CAs are in /data/misc/user/0/cacerts-added or /data/misc/user/0/cacerts
Process p = Runtime.getRuntime().exec(new String[]{"sh", "-c", "ls /data/misc/user/0/cacerts-added 2>/dev/null || ls /data/misc/user/0/cacerts 2>/dev/null"});
BufferedReader reader = new BufferedReader(new InputStreamReader(p.getInputStream()));
String line = reader.readLine();
reader.close();
if (line != null) return true;
}
} catch (Exception e) {
// ignore
}
return false;
}


private String getLocalIpAddress() {
try {
Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
for (NetworkInterface intf : Collections.list(interfaces)) {
Enumeration<InetAddress> addrs = intf.getInetAddresses();
for (InetAddress addr : Collections.list(addrs)) {
if (!addr.isLoopbackAddress()) {
String sAddr = addr.getHostAddress();
if (sAddr.indexOf(':') < 0) return sAddr; // return IPv4
}
}
}
} catch (Exception ex) { }
return null;
}
}
