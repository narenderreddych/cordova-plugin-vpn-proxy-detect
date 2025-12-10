#import <Cordova/CDV.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <net/if.h>
#import <UIKit/UIKit.h>

@interface VpnProxyDetect : CDVPlugin
- (void)check:(CDVInvokedUrlCommand*)command;
@end

@implementation VpnProxyDetect

- (void)check:(CDVInvokedUrlCommand*)command {

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

        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:res];
    }
    @catch (NSException *ex) {
        pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:ex.reason];
    }

    [self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}

#pragma mark - VPN Detection

- (BOOL)isVpnActive {
    struct ifaddrs *addrs;
    BOOL found = NO;

    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        while (cursor) {
            NSString *name = [NSString stringWithUTF8String:cursor->ifa_name].lowercaseString;
            if ([name hasPrefix:@"utun"] ||
                [name hasPrefix:@"ipsec"] ||
                [name hasPrefix:@"ppp"] ||
                [name hasPrefix:@"tap"]) {
                found = YES;
                break;
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
            [arr addObject:[NSString stringWithUTF8String:cursor->ifa_name]];
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    return arr;
}

#pragma mark - Local IP Address

- (NSString*)getLocalIp {
    struct ifaddrs *addrs;

    if (getifaddrs(&addrs) == 0) {
        struct ifaddrs *cursor = addrs;
        while (cursor) {
            if (cursor->ifa_addr->sa_family == AF_INET) {
                char addrBuf[INET_ADDRSTRLEN];
                struct sockaddr_in *sa = (struct sockaddr_in*)cursor->ifa_addr;
                inet_ntop(AF_INET, &(sa->sin_addr), addrBuf, INET_ADDRSTRLEN);

                NSString *name = [NSString stringWithUTF8String:cursor->ifa_name];
                if (![name hasPrefix:@"lo"]) {
                    freeifaddrs(addrs);
                    return [NSString stringWithUTF8String:addrBuf];
                }
            }
            cursor = cursor->ifa_next;
        }
        freeifaddrs(addrs);
    }
    return nil;
}

#pragma mark - Proxy Detection

- (BOOL)isProxyEnabled {
    NSDictionary *proxySettings = (__bridge_transfer NSDictionary *)CFNetworkCopySystemProxySettings();

    NSString *host = proxySettings[(NSString *)kCFNetworkProxiesHTTPProxy];
    NSNumber *port = proxySettings[(NSString *)kCFNetworkProxiesHTTPPort];

    if (host && port && host.length > 0) {
        return YES;
    }
    return NO;
}

#pragma mark - MITM Detection (Basic)

- (BOOL)isMitmPresent {
    // iOS does not allow detecting custom installed CAs reliably.
    // Keeping conservative false.
    return NO;
}

@end
