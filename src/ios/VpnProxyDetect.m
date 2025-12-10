#import <Cordova/CDV.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <CFNetwork/CFProxySupport.h>
#import <NetworkExtension/NetworkExtension.h>

@interface VpnProxyDetect : CDVPlugin
- (void)check:(CDVInvokedUrlCommand*)command;
@end

@implementation VpnProxyDetect

#pragma mark - Entry

- (void)check:(CDVInvokedUrlCommand*)command {

    [self.commandDelegate runInBackground:^{

        BOOL vpn = [self isVpnActive];
        BOOL proxy = [self isProxyEnabled];
        BOOL mitm = [self isMitmPresent];
        NSString *ip = [self getLocalIp];

        NSDictionary *res = @{
            @"vpnEnabled": @(vpn),
            @"proxyEnabled": @(proxy),
            @"mitmDetected": @(mitm),
            @"ip": ip ?: [NSNull null]
        };

        CDVPluginResult *result =
        [CDVPluginResult resultWithStatus:CDVCommandStatus_OK
                      messageAsDictionary:res];

        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }];
}

#pragma mark - REAL VPN DETECTION (Most reliable)

- (BOOL)isVpnActive {

    struct ifaddrs *interfaces;
    if (getifaddrs(&interfaces) != 0) return NO;

    BOOL isActive = NO;
    struct ifaddrs *cursor = interfaces;

    while (cursor != NULL) {

        NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];

        // Real VPN interface names (confirmed iOS 12–18)
        if ([name hasPrefix:@"ipsec"] ||     // IKEv2 / IPSec
            [name hasPrefix:@"ppp"]   ||     // L2TP / PPTP
            [name hasPrefix:@"utun"]  ||     // OpenVPN, WireGuard, SnapVPN etc
            [name hasPrefix:@"tap"]   ||     // Some custom VPNs
            [name hasPrefix:@"tun"]) {       // Tunnel types

            // Check if this interface has an IP assigned (not dummy)
            struct sockaddr_in *addr = (struct sockaddr_in *)cursor->ifa_addr;

            if (addr && addr->sin_family == AF_INET) {
                char ipStr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &addr->sin_addr, ipStr, INET_ADDRSTRLEN);

                NSString *ip = [NSString stringWithUTF8String:ipStr];

                // Exclude Localhost / NAT / Carrier pseudo IP
                if (![ip hasPrefix:@"0.0.0.0"] &&
                    ![ip hasPrefix:@"127."] &&
                    ip.length > 6) {

                    isActive = YES;
                    break;
                }
            }
        }

        cursor = cursor->ifa_next;
    }

    freeifaddrs(interfaces);
    return isActive;
}


#pragma mark - PROXY DETECTION

- (BOOL)isProxyEnabled {

    NSDictionary *proxySettings =
        (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();

    if (!proxySettings) return NO;

    NSString *host = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
    NSNumber *port = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];

    return (host && host.length > 0 && port != nil);
}

#pragma mark - MITM (Burp / Charles)

- (BOOL)isMitmPresent {

    @try {
        NSDictionary *proxySettings =
            (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();

        if (!proxySettings) return NO;

        NSString *host = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
        NSNumber *port = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];

        // Burp default ports: 8080, 8081, 8888
        if ([host isEqualToString:@"127.0.0.1"] ||
            [host isEqualToString:@"localhost"]) {

            if (port.intValue == 8080 ||
                port.intValue == 8081 ||
                port.intValue == 8888) {

                return YES;
            }
        }

    } @catch (NSException *e) {}

    return NO;
}

#pragma mark - LOCAL IP

- (NSString *)getLocalIp {

    struct ifaddrs *addrs;
    if (getifaddrs(&addrs) != 0) return nil;

    NSString *result = nil;
    struct ifaddrs *cursor = addrs;

    while (cursor) {

        if (cursor->ifa_addr->sa_family == AF_INET &&
            (cursor->ifa_flags & IFF_UP) &&
            (cursor->ifa_flags & IFF_RUNNING)) {

            char buf[INET_ADDRSTRLEN];
            struct sockaddr_in *sa = (struct sockaddr_in*)cursor->ifa_addr;

            inet_ntop(AF_INET, &sa->sin_addr, buf, INET_ADDRSTRLEN);

            NSString *ip = [NSString stringWithUTF8String:buf];
            NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];

            if (![ip hasPrefix:@"127."] &&
                ![ip hasPrefix:@"169.254"] &&
                ([name hasPrefix:@"en"] || [name hasPrefix:@"pdp_ip"])) {

                result = ip;
                break;
            }
        }

        cursor = cursor->ifa_next;
    }

    freeifaddrs(addrs);
    return result;
}

@end

