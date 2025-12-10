package com.vpndetect;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import android.util.Log;
import android.net.ProxyInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.content.Context;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.ArrayList;
import java.util.List;

public class VpnProxyDetect extends CordovaPlugin {
    private static final String TAG = "VpnProxyDetect";

    @Override
    public boolean execute(String action, JSONArray args, final CallbackContext callbackContext) {
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
                        res.put("interfaces", new JSONArray(ifaces));
                        res.put("ip", ip != null ? ip : JSONObject.NULL);

                        Log.d(TAG, "Results - VPN:" + vpn + " Proxy:" + proxy + " IP:" + ip);
                        callbackContext.success(res);
                    } catch (Exception e) {
                        Log.e(TAG, "Error", e);
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
                
                if (name.startsWith("tun") || name.startsWith("ppp") || name.contains("ipsec") ||
                    name.startsWith("utun") || name.startsWith("tap") || name.startsWith("wg") ||
                    name.startsWith("vti") || name.contains("vpn")) {
                    Log.d(TAG, "VPN interface: " + name);
                    return true;
                }
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                try {
                    Context context = cordova.getActivity().getApplicationContext();
                    ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
                    if (cm != null) {
                        Network activeNetwork = cm.getActiveNetwork();
                        if (activeNetwork != null) {
                            NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
                            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                                Log.d(TAG, "VPN via ConnectivityManager");
                                return true;
                            }
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "ConnectivityManager check failed", e);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "isVpnActive error", e);
        }
        return false;
    }

    private boolean isProxyActive() {
        String proxyHost = System.getProperty("http.proxyHost");
        String httpsProxyHost = System.getProperty("https.proxyHost");
        
        if ((proxyHost != null && !proxyHost.isEmpty()) || 
            (httpsProxyHost != null && !httpsProxyHost.isEmpty())) {
            Log.d(TAG, "Proxy via system: " + proxyHost + ", " + httpsProxyHost);
            return true;
        }
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.ICE_CREAM_SANDWICH) {
            try {
                String proxyAddress = android.net.Proxy.getHost(cordova.getActivity());
                if (proxyAddress != null && !proxyAddress.isEmpty()) {
                    Log.d(TAG, "Proxy via Android API: " + proxyAddress);
                    return true;
                }
            } catch (Exception e) {
                Log.w(TAG, "Android proxy check failed", e);
            }
        }
        return false;
    }

    private boolean isMitmPresent() {
        try {
            String proxyHost = System.getProperty("http.proxyHost");
            if (proxyHost != null && (proxyHost.contains("127.0.0.1") || proxyHost.contains("localhost"))) {
                String proxyPort = System.getProperty("http.proxyPort", "0");
                if (proxyPort.equals("8888") || proxyPort.equals("8889")) {
                    Log.d(TAG, "Possible MITM on port " + proxyPort);
                    return true;
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "isMitmPresent error", e);
        }
        return false;
    }

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

    private String getLocalIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface intf = interfaces.nextElement();
                if (!intf.isUp() || intf.isLoopback()) continue;
                
                Enumeration<InetAddress> addresses = intf.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (!addr.isLoopbackAddress() && addr.getAddress().length == 4) {
                        return addr.getHostAddress();
                    }
                }
            }
        } catch (SocketException e) {
            Log.e(TAG, "getLocalIpAddress error", e);
        }
        return null;
    }
}
