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
                    [name hasPrefix:@"tun"] || [name hasPrefix:@"wg"]) {
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

- (BOOL)isProxyEnabled {
    NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
    
    if (!proxySettings) return NO;
    
    NSString *httpHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
    NSString *httpsHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPSProxy];
    
    if ((httpHost && [httpHost isKindOfClass:[NSString class]] && httpHost.length > 0) ||
        (httpsHost && [httpsHost isKindOfClass:[NSString class]] && httpsHost.length > 0)) {
        NSLog(@"[VpnProxyDetect] Proxy detected: HTTP=%@, HTTPS=%@", httpHost, httpsHost);
        return YES;
    }
    
    return NO;
}

- (BOOL)isMitmPresent {
    @try {
        NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();
        
        if (proxySettings) {
            NSString *httpHost = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
            NSNumber *httpPort = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];
            
            if (httpHost && [httpHost isEqualToString:@"127.0.0.1"]) {
                if (httpPort && ([httpPort intValue] == 8888 || [httpPort intValue] == 8889)) {
                    NSLog(@"[VpnProxyDetect] MITM detected: local proxy on port %@", httpPort);
                    return YES;
                }
            }
        }
    }
    @catch (NSException *exception) {
        NSLog(@"[VpnProxyDetect] MITM detection error: %@", exception);
    }
    
    return NO;
}

@end
