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
            
            NSLog(@"[VPN-IOS] Result: VPN=%d, Proxy=%d, IP=%@", vpn, proxy, ip ?: @"null");
            
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:res];
        }
        @catch (NSException *ex) {
            NSLog(@"[VPN-IOS] Error: %@", ex.reason);
            pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:ex.reason];
        }
        
        [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
    }];
}

#pragma mark - VPN Detection (STRICT VERSION - NO FALSE POSITIVES)

- (BOOL)isVpnActive {
    struct ifaddrs *addrs;
    BOOL found = NO;
    
    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        
        NSLog(@"[VPN-IOS] === Scanning for VPN interfaces ===");
        
        while (cursor) {
            if (cursor->ifa_name) {
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                NSString *lowerName = name.lowercaseString;
                
                // CRITICAL: Interface MUST be UP and RUNNING
                BOOL isActive = (cursor->ifa_flags & IFF_UP) && (cursor->ifa_flags & IFF_RUNNING);
                
                if (isActive) {
                    // DEBUG: Log all active interfaces
                    NSLog(@"[VPN-IOS] Active interface: %@ (flags: %d)", name, cursor->ifa_flags);
                    
                    // ===== STRICT VPN DETECTION LOGIC =====
                    // ONLY these specific patterns count as VPN:
                    
                    // 1. utun1, utun2, utun3... (NOT utun0)
                    // utun0 is iOS system, utun1+ are usually VPNs
                    if ([lowerName hasPrefix:@"utun"] && ![lowerName isEqualToString:@"utun0"]) {
                        // Check if it's a numbered utun (utun1, utun2, etc.)
                        NSString *numberPart = [lowerName substringFromIndex:4]; // Remove "utun"
                        NSScanner *scanner = [NSScanner scannerWithString:numberPart];
                        int interfaceNumber;
                        if ([scanner scanInt:&interfaceNumber] && interfaceNumber >= 1) {
                            NSLog(@"[VPN-IOS] ✓ REAL VPN: %@ (utun%d)", name, interfaceNumber);
                            found = YES;
                            break;
                        }
                    }
                    
                    // 2. tun1, tun2, tun3... (NOT tun0)
                    else if ([lowerName hasPrefix:@"tun"] && ![lowerName isEqualToString:@"tun0"]) {
                        NSString *numberPart = [lowerName substringFromIndex:3]; // Remove "tun"
                        NSScanner *scanner = [NSScanner scannerWithString:numberPart];
                        int interfaceNumber;
                        if ([scanner scanInt:&interfaceNumber] && interfaceNumber >= 1) {
                            NSLog(@"[VPN-IOS] ✓ REAL VPN: %@ (tun%d)", name, interfaceNumber);
                            found = YES;
                            break;
                        }
                    }
                    
                    // 3. Other REAL VPN interfaces (must be active)
                    else if ([lowerName hasPrefix:@"ipsec"] || 
                             [lowerName hasPrefix:@"ppp"] ||
                             [lowerName hasPrefix:@"tap"] ||
                             [lowerName hasPrefix:@"wg"] ||
                             [lowerName hasPrefix:@"vti"]) {
                        NSLog(@"[VPN-IOS] ✓ REAL VPN: %@", name);
                        found = YES;
                        break;
                    }
                    
                    // 4. EXPLICITLY IGNORE non-VPN interfaces
                    else if ([lowerName hasPrefix:@"pdp_ip"] ||  // Cellular
                             [lowerName hasPrefix:@"en"] ||      // WiFi/Ethernet
                             [lowerName hasPrefix:@"ap"] ||      // Access Point
                             [lowerName hasPrefix:@"lo"] ||      // Loopback
                             [lowerName hasPrefix:@"awdl"] ||    // Apple Wireless
                             [lowerName hasPrefix:@"llw"] ||     // Low Latency WiFi
                             [lowerName hasPrefix:@"XHC"]) {     // USB
                        // These are NOT VPN - explicitly ignored
                        NSLog(@"[VPN-IOS]   Non-VPN: %@", name);
                    }
                }
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
        
        NSLog(@"[VPN-IOS] === VPN Result: %@ ===", found ? @"DETECTED" : @"NOT DETECTED");
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
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                
                // Add interface flags info
                NSString *flags = @"";
                if (cursor->ifa_flags & IFF_UP) flags = [flags stringByAppendingString:@"U"];
                if (cursor->ifa_flags & IFF_RUNNING) flags = [flags stringByAppendingString:@"R"];
                if (cursor->ifa_flags & IFF_LOOPBACK) flags = [flags stringByAppendingString:@"L"];
                
                // Only add unique interfaces with their flags
                NSString *interfaceInfo = [NSString stringWithFormat:@"%@[%@]", name, flags];
                if (![arr containsObject:interfaceInfo]) {
                    [arr addObject:interfaceInfo];
                }
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
                // Skip interfaces that aren't up and running
                if (!(cursor->ifa_flags & IFF_UP) || !(cursor->ifa_flags & IFF_RUNNING)) {
                    cursor = cursor->ifa_next;
                    continue;
                }
                
                char addrBuf[INET_ADDRSTRLEN];
                struct sockaddr_in *sa = (struct sockaddr_in*)cursor->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), addrBuf, INET_ADDRSTRLEN);
                
                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                NSString *address = [NSString stringWithUTF8String:addrBuf];
                
                // Skip loopback and link-local addresses
                if ([address hasPrefix:@"127."] || [address hasPrefix:@"169.254."]) {
                    cursor = cursor->ifa_next;
                    continue;
                }
                
                // Prefer WiFi (en0, en1, etc.)
                if ([name hasPrefix:@"en"]) {
                    wifiAddress = address;
                }
                // Then cellular (pdp_ip*)
                else if ([name hasPrefix:@"pdp_ip"]) {
                    cellularAddress = address;
                }
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    
    // Return in order of preference
    if (wifiAddress) {
        return wifiAddress;
    } else if (cellularAddress) {
        return cellularAddress;
    }
    
    return nil;
}

#pragma mark - Proxy Detection

- (BOOL)isProxyEnabled {
    NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
    
    if (!proxySettings) {
        return NO;
    }
    
    NSString *proxyHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
    NSNumber *proxyPort = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];
    
    if (proxyHost && [proxyHost isKindOfClass:[NSString class]] && proxyHost.length > 0) {
        NSLog(@"[VPN-IOS] HTTP Proxy: %@:%@", proxyHost, proxyPort);
        return YES;
    }
    
    return NO;
}

#pragma mark - MITM Detection

- (BOOL)isMitmPresent {
    @try {
        NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
        
        if (proxySettings) {
            NSString *proxyHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
            NSNumber *proxyPort = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];
            
            if (proxyHost && [proxyHost isEqualToString:@"127.0.0.1"]) {
                if (proxyPort && ([proxyPort intValue] == 8888 || [proxyPort intValue] == 8889)) {
                    NSLog(@"[VPN-IOS] MITM: local proxy on port %@", proxyPort);
                    return YES;
                }
            }
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[VPN-IOS] MITM error: %@", exception);
    }
    
    return NO;
}

@end
