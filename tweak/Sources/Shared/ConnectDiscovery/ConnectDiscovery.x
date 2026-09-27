#import "Core/SGCore.h"
#import "Core/SGRebind.h"
#import <errno.h>
#import <arpa/inet.h>
#import <netinet/in.h>
#import <QuartzCore/QuartzCore.h>
#import <stdbool.h>
#import <stdatomic.h>
#import <string.h>
#import <sys/socket.h>
#import <sys/time.h>
#import <sys/uio.h>
#import <unistd.h>

static ssize_t (*sg_originalSendTo)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*sg_originalSendMsg)(int, const struct msghdr *, int);
static ssize_t (*sg_originalSend)(int, const void *, size_t, int);
static ssize_t (*sg_originalRecvFrom)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
static ssize_t (*sg_originalRecvMsg)(int, struct msghdr *, int);
static NSObject *sg_discoveryLock;
static NSMutableArray<NSDictionary *> *sg_bonjourTargets;
static NSMutableArray<NSDictionary *> *sg_injectedPackets;
static atomic_bool sg_hasInjectedPackets;
static CFTimeInterval sg_lastBridgeAttempt;
static dispatch_queue_t sg_bridgeQueue;

@interface SGConnectTargetBrowser : NSObject <NSNetServiceBrowserDelegate, NSNetServiceDelegate>
@property (nonatomic, strong) NSNetServiceBrowser *browser;
@property (nonatomic, strong) NSMutableArray<NSNetService *> *services;
@property (nonatomic, strong) NSMutableSet<NSString *> *resolving;
- (void)start;
@end

static SGConnectTargetBrowser *sg_targetBrowser;

// Called while sg_discoveryLock is held so a receive cannot overtake the record.
static void rememberInjectedPacketLocked(int fd, const void *bytes, size_t length, const struct sockaddr_in *source) {
    if (!bytes || length < 12 || !source) return;
    NSDictionary *packet = @{
        @"bytes": [NSData dataWithBytes:bytes length:length],
        @"fd": @(fd),
        @"source": [NSData dataWithBytes:source length:sizeof(*source)],
        @"time": @(CACurrentMediaTime())
    };
    CFTimeInterval now = CACurrentMediaTime();
    NSIndexSet *expired = [sg_injectedPackets indexesOfObjectsPassingTest:^BOOL(NSDictionary *entry, NSUInteger idx, BOOL *stop) {
        return now - [entry[@"time"] doubleValue] > 15.0;
    }];
    [sg_injectedPackets removeObjectsAtIndexes:expired];
    [sg_injectedPackets addObject:packet];
    atomic_store(&sg_hasInjectedPackets, true);
}

static BOOL isLoopbackSource(const struct sockaddr *source, socklen_t length) {
    if (!source) return NO;
    if (source->sa_family == AF_INET && length >= sizeof(struct sockaddr_in))
        return ntohl(((const struct sockaddr_in *)source)->sin_addr.s_addr) == INADDR_LOOPBACK;
    if (source->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6))
        return IN6_IS_ADDR_LOOPBACK(&((const struct sockaddr_in6 *)source)->sin6_addr);
    return NO;
}

static BOOL matchInjectedPacket(int fd, const void *bytes, size_t length, struct sockaddr *source, socklen_t *sourceLength) {
    if (!atomic_load(&sg_hasInjectedPackets)) return NO;
    if (!bytes || length < 12 || !( ((const unsigned char *)bytes)[2] & 0x80 )) return NO;
    if (!source || !sourceLength || !isLoopbackSource(source, *sourceLength)) return NO;
    @synchronized (sg_discoveryLock) {
        CFTimeInterval now = CACurrentMediaTime();
        for (NSInteger i = (NSInteger)sg_injectedPackets.count - 1; i >= 0; i--) {
            NSDictionary *entry = sg_injectedPackets[(NSUInteger)i];
            if (now - [entry[@"time"] doubleValue] > 15.0) {
                [sg_injectedPackets removeObjectAtIndex:(NSUInteger)i];
                if (!sg_injectedPackets.count) atomic_store(&sg_hasInjectedPackets, false);
                continue;
            }
            if ([entry[@"fd"] intValue] != fd) continue;
            NSData *expected = entry[@"bytes"];
            if (length > expected.length || memcmp(expected.bytes, bytes, length) != 0) continue;

            const struct sockaddr_in *ipv4 = [entry[@"source"] bytes];
            if (source->sa_family == AF_INET6 && *sourceLength >= sizeof(struct sockaddr_in6)) {
                struct sockaddr_in6 mapped = {0};
                mapped.sin6_family = AF_INET6;
                mapped.sin6_port = ipv4->sin_port;
                mapped.sin6_addr.s6_addr[10] = 0xff;
                mapped.sin6_addr.s6_addr[11] = 0xff;
                memcpy(&mapped.sin6_addr.s6_addr[12], &ipv4->sin_addr, sizeof(ipv4->sin_addr));
                memcpy(source, &mapped, sizeof(mapped));
                *sourceLength = sizeof(mapped);
            } else if (source->sa_family == AF_INET && *sourceLength >= sizeof(struct sockaddr_in)) {
                memcpy(source, ipv4, sizeof(*ipv4));
                *sourceLength = sizeof(*ipv4);
            }
            return YES;
        }
    }
    return NO;
}

static BOOL containsConnectQuestion(const void *bytes, size_t length) {
    static const char needle[] = "_spotify-connect";
    if (!bytes || length < sizeof(needle) - 1) return NO;
    const unsigned char *p = bytes;
    for (size_t i = 0; i + sizeof(needle) - 1 <= length; i++) {
        if (memcmp(p + i, needle, sizeof(needle) - 1) == 0) return YES;
    }
    return NO;
}

static BOOL isMulticastDNS(const struct sockaddr *address, socklen_t length) {
    if (!address) return NO;
    if (address->sa_family == AF_INET && length >= sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)address;
        return ipv4->sin_port == htons(5353) && ipv4->sin_addr.s_addr == htonl(0xe00000fb);
    }
    if (address->sa_family == AF_INET6 && length >= sizeof(struct sockaddr_in6)) {
        static const unsigned char mdns6[16] = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb};
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)address;
        return ipv6->sin6_port == htons(5353) && memcmp(&ipv6->sin6_addr, mdns6, sizeof(mdns6)) == 0;
    }
    return NO;
}

@implementation SGConnectTargetBrowser

- (void)start {
    self.services = [NSMutableArray array];
    self.resolving = [NSMutableSet set];
    self.browser = [NSNetServiceBrowser new];
    self.browser.delegate = self;
    [self.browser searchForServicesOfType:@"_spotify-connect._tcp." inDomain:@"local."];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)moreComing {
    if ([self.resolving containsObject:service.name]) return;
    [self.resolving addObject:service.name];
    service.delegate = self;
    [self.services addObject:service];
    [service resolveWithTimeout:5.0];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didRemoveService:(NSNetService *)service moreComing:(BOOL)moreComing {
    [self.resolving removeObject:service.name];
    [self.services removeObject:service];
    @synchronized (sg_discoveryLock) {
        NSIndexSet *matches = [sg_bonjourTargets indexesOfObjectsPassingTest:^BOOL(NSDictionary *target, NSUInteger idx, BOOL *stop) {
            return [target[@"name"] isEqualToString:service.name];
        }];
        [sg_bonjourTargets removeObjectsAtIndexes:matches];
    }
}

- (void)netServiceDidResolveAddress:(NSNetService *)service {
    NSMutableArray<NSDictionary *> *resolved = [NSMutableArray array];
    for (NSData *data in service.addresses) {
        if (data.length < sizeof(struct sockaddr_in)) continue;
        const struct sockaddr *address = data.bytes;
        if (address->sa_family != AF_INET) continue;
        struct sockaddr_in target = *(const struct sockaddr_in *)address;
        target.sin_port = htons(5353);
        [resolved addObject:@{ @"name": service.name, @"address": [NSData dataWithBytes:&target length:sizeof(target)] }];
    }
    @synchronized (sg_discoveryLock) {
        NSIndexSet *matches = [sg_bonjourTargets indexesOfObjectsPassingTest:^BOOL(NSDictionary *target, NSUInteger idx, BOOL *stop) {
            return [target[@"name"] isEqualToString:service.name];
        }];
        [sg_bonjourTargets removeObjectsAtIndexes:matches];
        [sg_bonjourTargets addObjectsFromArray:resolved];
    }
    if (resolved.count) SGLog(@"Connect unicast bridge: resolved %@ to %lu IPv4 address(es)", service.name, (unsigned long)resolved.count);
}

- (void)netService:(NSNetService *)service didNotResolve:(NSDictionary<NSString *,NSNumber *> *)errorDict {
    SGLog(@"Connect unicast bridge: could not resolve %@ (%@)", service.name, errorDict);
}

@end

// Spotify's socket is already bound to the mDNS port. Ask each Bonjour-resolved receiver from an
// ephemeral unicast socket (so its answer comes back unicast), then inject the DNS answer into
// Spotify's own socket on loopback. Unicast and loopback UDP are permitted without Apple's multicast
// entitlement; this only runs after Spotify's matching multicast send has failed.
static BOOL bridgeFailedQuery(int fd, NSData *query) {
    NSArray<NSDictionary *> *targets;
    CFTimeInterval now = CACurrentMediaTime();
    int retainedFD = -1;
    @synchronized (sg_discoveryLock) {
        if (!sg_bonjourTargets.count) return NO;
        // Another failed send already started a bridge round for the same receiver.
        if (now - sg_lastBridgeAttempt < 1.0) return YES;
        retainedFD = dup(fd);
        if (retainedFD < 0) return NO;
        sg_lastBridgeAttempt = now;
        targets = [sg_bonjourTargets copy];
    }
    dispatch_async(sg_bridgeQueue, ^{
        for (NSDictionary *entry in targets) {
            NSData *addressData = entry[@"address"];
            if (addressData.length != sizeof(struct sockaddr_in)) continue;
            const struct sockaddr_in *target = addressData.bytes;
            int probeFD = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (probeFD < 0) continue;
            struct timeval timeout = { .tv_sec = 0, .tv_usec = 450000 };
            setsockopt(probeFD, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
            ssize_t sent = sendto(probeFD, query.bytes, query.length, 0, (const struct sockaddr *)target, sizeof(*target));
            unsigned char response[1500];
            ssize_t received = sent < 0 ? -1 : recvfrom(probeFD, response, sizeof(response), 0, NULL, NULL);
            close(probeFD);
            if (received < 12 || !(response[2] & 0x80)) continue;

            struct sockaddr_storage local = {0};
            socklen_t localLength = sizeof(local);
            if (getsockname(retainedFD, (struct sockaddr *)&local, &localLength) != 0) continue;
            ssize_t injected = -1;
            if (local.ss_family == AF_INET6) {
                struct sockaddr_in6 loopback = {0};
                loopback.sin6_family = AF_INET6;
                loopback.sin6_port = ((struct sockaddr_in6 *)&local)->sin6_port;
                loopback.sin6_addr = in6addr_loopback;
                @synchronized (sg_discoveryLock) {
                    injected = sendto(retainedFD, response, (size_t)received, 0,
                                      (struct sockaddr *)&loopback, sizeof(loopback));
                    if (injected == received) rememberInjectedPacketLocked(fd, response, (size_t)received, target);
                }
            } else if (local.ss_family == AF_INET) {
                struct sockaddr_in loopback = {0};
                loopback.sin_family = AF_INET;
                loopback.sin_port = ((struct sockaddr_in *)&local)->sin_port;
                loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
                @synchronized (sg_discoveryLock) {
                    injected = sendto(retainedFD, response, (size_t)received, 0,
                                      (struct sockaddr *)&loopback, sizeof(loopback));
                    if (injected == received) rememberInjectedPacketLocked(fd, response, (size_t)received, target);
                }
            }
            if (injected == received) {
                SGLog(@"Connect unicast bridge: injected %ld-byte response from %@", (long)received, entry[@"name"]);
            }
        }
        close(retainedFD);
    });
    return YES;
}

static ssize_t bridgeSendTo(int fd, const void *bytes, size_t length, int flags,
                           const struct sockaddr *address, socklen_t addressLength) {
    BOOL matching = isMulticastDNS(address, addressLength) && containsConnectQuestion(bytes, length);
    ssize_t result = sg_originalSendTo(fd, bytes, length, flags, address, addressLength);
    int savedError = errno;
    if (matching && result < 0 && bridgeFailedQuery(fd, [NSData dataWithBytes:bytes length:length])) {
        errno = savedError;
        return (ssize_t)length;
    }
    errno = savedError;
    return result;
}

static ssize_t bridgeSendMsg(int fd, const struct msghdr *message, int flags) {
    ssize_t result = sg_originalSendMsg(fd, message, flags);
    int savedError = errno;
    if (result < 0 && message && message->msg_iov && message->msg_iovlen > 0) {
        struct sockaddr_storage peer = {0};
        socklen_t peerLength = sizeof(peer);
        const struct sockaddr *destination = message->msg_name;
        socklen_t destinationLength = message->msg_namelen;
        if (!destination && getpeername(fd, (struct sockaddr *)&peer, &peerLength) == 0) {
            destination = (const struct sockaddr *)&peer;
            destinationLength = peerLength;
        }
        if (isMulticastDNS(destination, destinationLength)) {
            size_t total = 0;
            for (int i = 0; i < message->msg_iovlen; i++) {
                if (message->msg_iov[i].iov_len > 1500 - total) { total = 1501; break; }
                total += message->msg_iov[i].iov_len;
            }
            if (total <= 1500) {
                NSMutableData *query = [NSMutableData dataWithCapacity:total];
                for (int i = 0; i < message->msg_iovlen; i++)
                    [query appendBytes:message->msg_iov[i].iov_base length:message->msg_iov[i].iov_len];
                if (containsConnectQuestion(query.bytes, query.length) && bridgeFailedQuery(fd, query)) {
                    errno = savedError;
                    return (ssize_t)query.length;
                }
            }
        }
    }
    errno = savedError;
    return result;
}

static ssize_t bridgeSend(int fd, const void *bytes, size_t length, int flags) {
    struct sockaddr_storage peer = {0};
    socklen_t peerLength = sizeof(peer);
    BOOL matching = containsConnectQuestion(bytes, length)
        && getpeername(fd, (struct sockaddr *)&peer, &peerLength) == 0
        && isMulticastDNS((struct sockaddr *)&peer, peerLength);
    ssize_t result = sg_originalSend(fd, bytes, length, flags);
    int savedError = errno;
    if (matching && result < 0 && bridgeFailedQuery(fd, [NSData dataWithBytes:bytes length:length])) {
        errno = savedError;
        return (ssize_t)length;
    }
    errno = savedError;
    return result;
}

static ssize_t bridgeRecvFrom(int fd, void *bytes, size_t length, int flags,
                             struct sockaddr *source, socklen_t *sourceLength) {
    ssize_t result = sg_originalRecvFrom(fd, bytes, length, flags, source, sourceLength);
    if (result > 0) matchInjectedPacket(fd, bytes, (size_t)result, source, sourceLength);
    return result;
}

static ssize_t bridgeRecvMsg(int fd, struct msghdr *message, int flags) {
    ssize_t result = sg_originalRecvMsg(fd, message, flags);
    if (result < 12 || result > 1500 || !message || !message->msg_name || !atomic_load(&sg_hasInjectedPackets)) return result;
    NSMutableData *bytes = [NSMutableData dataWithLength:(NSUInteger)result];
    size_t copied = 0;
    for (int i = 0; i < message->msg_iovlen && copied < (size_t)result; i++) {
        size_t part = MIN(message->msg_iov[i].iov_len, (size_t)result - copied);
        memcpy((char *)bytes.mutableBytes + copied, message->msg_iov[i].iov_base, part);
        copied += part;
    }
    if (copied == (size_t)result) {
        socklen_t sourceLength = message->msg_namelen;
        matchInjectedPacket(fd, bytes.bytes, bytes.length, message->msg_name, &sourceLength);
        message->msg_namelen = sourceLength;
    }
    return result;
}

%ctor {
    sg_discoveryLock = [NSObject new];
    sg_bonjourTargets = [NSMutableArray array];
    sg_injectedPackets = [NSMutableArray array];
    sg_bridgeQueue = dispatch_queue_create("com.spotifyglass.connect-unicast-bridge", DISPATCH_QUEUE_SERIAL);
    SGRebindImport("sendto", bridgeSendTo, (void **)&sg_originalSendTo);
    SGRebindImport("sendmsg", bridgeSendMsg, (void **)&sg_originalSendMsg);
    SGRebindImport("send", bridgeSend, (void **)&sg_originalSend);
    SGRebindImport("recvfrom", bridgeRecvFrom, (void **)&sg_originalRecvFrom);
    SGRebindImport("recvmsg", bridgeRecvMsg, (void **)&sg_originalRecvMsg);
    dispatch_async(dispatch_get_main_queue(), ^{
        sg_targetBrowser = [SGConnectTargetBrowser new];
        [sg_targetBrowser start];
    });
}
