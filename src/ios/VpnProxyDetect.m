#import <Cordova/CDV.h>
NSString *ip = [self getLocalIp];


NSDictionary *res = @{
@"vpnEnabled": @(vpn),
@"proxyEnabled": @(proxy),
@"mitmDetected": @(mitm),
@"interfaces": (ifaces ? ifaces : @[]),
@"ip": (ip ? ip : [NSNull null])
};


pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:res];
}
@catch (NSException *ex) {
pluginResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:ex.reason];
}


[self.commandDelegate sendPluginResult:pluginResult callbackId:command.callbackId];
}


- (BOOL)isVpnActive {
struct ifaddrs *addrs;
BOOL found = NO;
if (getifaddrs(&addrs) == 0) {
struct ifaddrs *cursor = addrs;
while (cursor) {
NSString *name = [NSString stringWithUTF8String:cursor->ifa_name].lowercaseString;
if ([name hasPrefix:@"utun"] || [name hasPrefix:@"ipsec"] || [name hasPrefix:@"ppp"] || [name hasPrefix:@"tap"]) {
found = YES; break;
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
[arr addObject:[NSString stringWithUTF8String:cursor->ifa_name]];
cursor = cursor->ifa_next;
}
freeifaddrs(addrs);
}
return arr;
}


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


- (BOOL)isProxyEnabled {
NSDictionary *proxySettings = (__bridge NSDictionary *)CFNetworkCopySystemProxySettings();
id host = [proxySettings objectForKey:(NSString *)kCFNetworkProxiesHTTPProxy];
id port = [proxySettings objectForKey:(NSString *)kCFNetworkProxiesHTTPPort];
if (host && port) return YES;
return NO;
}


- (BOOL)isMitmPresent {
// iOS: hard to detect user CA injection reliably. Best-effort: check for presence of extra certs is restricted.
return NO; // keep conservative false; recommend server-side checks for MITM
}


@end
