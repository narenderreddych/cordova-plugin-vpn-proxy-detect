package com.vpndetect;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Log;

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

    /** VPN detection based on network interface names */
    private boolean isVpnActive() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface intf : Collections.list(interfaces)) {
                String name = intf.getName().toLowerCase();
                if (!intf.isUp()) continue;
                if (name.startsWith("tun") || name.startsWith("ppp") || name.contains("ipsec") ||
                    name.startsWith("utun") || name.startsWith("tap") || name.startsWith("wg") ||
                    name.startsWith("vti")) {
                    Log.d(TAG, "Detected VPN interface: " + name);
                    return true;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "isVpnActive error", e);
        }
        return false;
    }

    /** Proxy detection using system properties */
    private boolean isProxyActive() {
        String proxyHost = System.getProperty("http.proxyHost");
        return proxyHost != null && !proxyHost.isEmpty();
    }

    /** MITM detection stub (not implemented) */
    private boolean isMitmPresent() {
        // Advanced MITM detection is complex; returning false for now
        return false;
    }

    /** Return all network interface names */
    private List<String> getInterfaceNames() {
        List<String> names = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            for (NetworkInterface intf : Collections.list(interfaces)) {
                names.add(intf.getName());
            }
        } catch (Exception e) {
            Log.e(TAG, "getInterfaceNames error", e);
        }
        return names;
    }

    /** Stub for local IP address (can implement actual detection) */
    private String getLocalIpAddress() {
        return null; // return null for now
    }
}
