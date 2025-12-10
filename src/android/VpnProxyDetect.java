package com.vpndetect;


import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaWebView;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;


import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.util.Log;


import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.List;


public class VpnProxyDetect extends CordovaPlugin {
private static final String TAG = "VpnProxyDetect";


@Override
public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) throws JSONException {
if (action.equals("check")) {
cordova.getThreadPool().execute(new Runnable() {
public void run() {
try {
JSONObject res = new JSONObject();
boolean vpn = isVpnActive();
boolean proxy = isProxyActive();
boolean mitm = isMitmPresent();


List<String> ifaces = getInterfaceNames();
String ip = getLocalIpAddress();


res.put("vpnEnabled", vpn);
res.put("proxyEnabled", proxy);
res.put("mitmDetected", mitm);
res.put("interfaces", ifaces);
res.put("ip", ip == null ? JSONObject.NULL : ip);


callbackContext.success(res);
} catch (Exception e) {
callbackContext.error(e.getMessage());
}
}
});
return true;
}
return false;
}


private boolean isVpnActive() {
try {
Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
for (NetworkInterface intf : Collections.list(interfaces)) {
String name = intf.getName().toLowerCase();
if (!intf.isUp()) continue;
if (name.startsWith("tun") || name.startsWith("ppp") || name.contains("ipsec") || name.startsWith("utun") || name.startsWith("tap") || name.startsWith("wg") || name.startsWith("vti")) {
Log.d(TAG, "Detected VPN interface: " + name);
return true;
}
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
