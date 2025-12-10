#import <Cordova/CDV.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <UIKit/UIKit.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CFNetwork/CFProxySupport.h>

@interface VpnProxyDetect : CDVPlugin
- (void)check:(CDVInvokedUrlCommand*)command;
@end

@implementation VpnProxyDetect

- (void)check:(CDVInvokedUrlCommand*)command {
    [self.commandDelegate runInBackground:^{
        CDVPluginResult *pluginResult = nil;
        
        @try {
            BOOL vpn = [self isVpnActive];
            BOOL proxy = [self isProxyEnabled];
            BOOL mitm = [self isMitmPresent];
            NSArray *ifaces = [self getInterfaceNames];
            NSString *ip = [self getLocalIp];
            
            NSDictionary *res = @{
                @"vpnEnabled": @(vpn),
                @"proxyEnabled": @(proxy),
                @"mitmDetected": @(mitm),
                @"interfaces": ifaces ?: @[],
                @"ip": ip ?: [NSNull null]
            };
            
            NSLog(@"[VpnProxyDetect] VPN:%d Proxy:%d IP:%@", vpn, proxy, ip ?: @"null");
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:res];
        }
        @catch (NSException *ex) {
            NSLog(@"[VpnProxyDetect] Error: %@", ex.reason);
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:ex.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

#pragma mark - VPN Detection

- (BOOL)isVpnActive {
    struct ifaddrs *addrs;
    BOOL found = NO;
    
    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        while (cursor) {
            if (cursor->ifa_name) {
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name].lowercaseString;
                
                if ([name hasPrefix:@"utun"] || [name hasPrefix:@"ipsec"] || 
                    [name hasPrefix:@"ppp"] || [name hasPrefix:@"tap"] ||
                    [name hasPrefix:@"tun"] || [name hasPrefix:@"wg"] ||
                    [name containsString:@"ipsec"]) {
                    NSLog(@"[VpnProxyDetect] VPN interface: %@", name);
                    found = YES;
                    break;
                }
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    return found;
}

#pragma mark - Interface List

- (NSArray*)getInterfaceNames {
    NSMutableArray *arr = [NSMutableArray array];
    struct ifaddrs *addrs;
    
    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        while (cursor) {
            if (cursor->ifa_name) {
                [arr addObject:[NSString stringWithUTF8String:cursor->ifa_name]];
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    return arr;
}

#pragma mark - Local IP Address

- (NSString*)getLocalIp {
    struct ifaddrs *addrs;
    NSString *wifiAddress = nil;
    NSString *cellularAddress = nil;
    
    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        while (cursor) {
            if (cursor->ifa_addr && cursor->ifa_addr->sa_family == AF_INET) {
                char addrBuf[INET_ADDRSTRLEN];
                struct sockaddr_in *sa = (struct sockaddr_in*)cursor->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), addrBuf, INET_ADDRSTRLEN);
                
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                NSString *address = [NSString stringWithUTF8String:addrBuf];
                
                if ([name hasPrefix:@"en"]) {
                    wifiAddress = address;
                } else if ([name hasPrefix:@"pdp_ip"]) {
                    cellularAddress = address;
                } else if (![name hasPrefix:@"lo"] && !wifiAddress && !cellularAddress) {
                    wifiAddress = address;
                }
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    
    return wifiAddress ?: cellularAddress;
}

#pragma mark - Proxy Detection (iOS-Compatible)

- (BOOL)isProxyEnabled {
    NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
    
    if (!proxySettings) {
        return NO;
    }
    
    // iOS only has HTTP proxy settings, not separate HTTPS proxy
    // Check for HTTP proxy
    NSString *proxyHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
    NSNumber *proxyPort = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];
    
    if (proxyHost && [proxyHost isKindOfClass:[NSString class]] && proxyHost.length > 0) {
        NSLog(@"[VpnProxyDetect] HTTP Proxy detected: %@:%@", proxyHost, proxyPort);
        return YES;
    }
    
    // Check for proxy auto-configuration (PAC)
    NSString *pacUrl = proxySettings[(NSString *)kCFNetworkProxiesProxyAutoConfigURLString];
    if (pacUrl && [pacUrl isKindOfClass:[NSString class]] && pacUrl.length > 0) {
        NSLog(@"[VpnProxyDetect] PAC proxy detected: %@", pacUrl);
        return YES;
    }
    
    // Check if proxy is enabled (iOS-specific key)
    NSNumber *proxyEnabled = proxySettings[(NSString *)kCFNetworkProxiesHTTPEnable];
    if (proxyEnabled && [proxyEnabled boolValue]) {
        NSLog(@"[VpnProxyDetect] Proxy enabled via kCFNetworkProxiesHTTPEnable");
        return YES;
    }
    
    // Additional check: iOS sometimes uses __SCOPED__ dictionary
    NSDictionary *scopedSettings = proxySettings[@"__SCOPED__"];
    if (scopedSettings && [scopedSettings isKindOfClass:[NSDictionary class]]) {
        for (NSString *key in scopedSettings) {
            NSDictionary *scopedProxy = scopedSettings[key];
            if (scopedProxy && scopedProxy[(NSString *)kCFNetworkProxiesHTTPProxy]) {
                NSLog(@"[VpnProxyDetect] Scoped proxy found for interface: %@", key);
                return YES;
            }
        }
    }
    
    return NO;
}

#pragma mark - MITM Detection (iOS-Compatible)

- (BOOL)isMitmPresent {
    @try {
        NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
        
        if (proxySettings) {
            NSString *proxyHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
            NSNumber *proxyPort = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];
            
            // Check for common MITM proxy ports on localhost
            if (proxyHost && [proxyHost isEqualToString:@"127.0.0.1"]) {
                if (proxyPort && ([proxyPort intValue] == 8888 || [proxyPort intValue] == 8889 || 
                                  [proxyPort intValue] == 8080 || [proxyPort intValue] == 8081)) {
                    NSLog(@"[VpnProxyDetect] Possible MITM detected: local proxy on port %@", proxyPort);
                    return YES;
                }
            }
            
            // Check if any proxy auto-config URL contains "mitm" or "proxy"
            NSString *pacUrl = proxySettings[(NSString *)kCFNetworkProxiesProxyAutoConfigURLString];
            if (pacUrl && [pacUrl rangeOfString:@"mitm" options:NSCaseInsensitiveSearch].location != NSNotFound) {
                NSLog(@"[VpnProxyDetect] MITM indicated in PAC URL: %@", pacUrl);
                return YES;
            }
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[VpnProxyDetect] MITM detection error: %@", exception);
    }
    
    return NO;
}

@end
