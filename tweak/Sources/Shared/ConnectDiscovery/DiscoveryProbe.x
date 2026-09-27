#import "Core/SGCore.h"
#import "Core/SGRebind.h"
#import "DiscoveryProbe.h"
#import <errno.h>
#import <netinet/in.h>
#import <string.h>
#import <sys/socket.h>

static ssize_t (*sg_originalSendTo)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
static ssize_t (*sg_originalSendMsg)(int, const struct msghdr *, int);
static ssize_t (*sg_originalSend)(int, const void *, size_t, int);
static NSObject *sg_probeLock;
static NSString *sg_lastAttempt;
static NSUInteger sg_attempts;
static BOOL sg_hookedSendTo;
static BOOL sg_hookedSendMsg;
static BOOL sg_hookedSend;

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

static void recordAttempt(int fd, NSString *function, ssize_t result, int error) {
    struct sockaddr_storage local = {0};
    socklen_t length = sizeof(local);
    NSString *source = @"unknown";
    if (getsockname(fd, (struct sockaddr *)&local, &length) == 0) {
        if (local.ss_family == AF_INET) {
            source = [NSString stringWithFormat:@"IPv4 port %u", ntohs(((struct sockaddr_in *)&local)->sin_port)];
        } else if (local.ss_family == AF_INET6) {
            source = [NSString stringWithFormat:@"IPv6 port %u", ntohs(((struct sockaddr_in6 *)&local)->sin6_port)];
        }
    }
    NSString *status = result < 0 ? [NSString stringWithFormat:@"failed (errno %d: %s)", error, strerror(error)] : @"sent";
    NSString *attempt = [NSString stringWithFormat:@"%@: %@ from %@", function, status, source];
    @synchronized (sg_probeLock) {
        sg_attempts++;
        sg_lastAttempt = attempt;
    }
    SGLog(@"Connect raw discovery: %@", attempt);
}

static ssize_t probeSendTo(int fd, const void *bytes, size_t length, int flags,
                           const struct sockaddr *address, socklen_t addressLength) {
    BOOL matching = isMulticastDNS(address, addressLength) && containsConnectQuestion(bytes, length);
    ssize_t result = sg_originalSendTo(fd, bytes, length, flags, address, addressLength);
    int savedError = errno;
    if (matching) recordAttempt(fd, @"sendto", result, savedError);
    errno = savedError;
    return result;
}

static ssize_t probeSendMsg(int fd, const struct msghdr *message, int flags) {
    BOOL matching = NO;
    if (message && isMulticastDNS(message->msg_name, message->msg_namelen)) {
        for (int i = 0; i < message->msg_iovlen; i++) {
            if (containsConnectQuestion(message->msg_iov[i].iov_base, message->msg_iov[i].iov_len)) {
                matching = YES;
                break;
            }
        }
    }
    ssize_t result = sg_originalSendMsg(fd, message, flags);
    int savedError = errno;
    if (matching) recordAttempt(fd, @"sendmsg", result, savedError);
    errno = savedError;
    return result;
}

static ssize_t probeSend(int fd, const void *bytes, size_t length, int flags) {
    struct sockaddr_storage peer = {0};
    socklen_t peerLength = sizeof(peer);
    BOOL matching = containsConnectQuestion(bytes, length)
        && getpeername(fd, (struct sockaddr *)&peer, &peerLength) == 0
        && isMulticastDNS((struct sockaddr *)&peer, peerLength);
    ssize_t result = sg_originalSend(fd, bytes, length, flags);
    int savedError = errno;
    if (matching) recordAttempt(fd, @"send", result, savedError);
    errno = savedError;
    return result;
}

NSString *SGConnectRawDiscoverySnapshot(void) {
    @synchronized (sg_probeLock) {
        if (!sg_hookedSendTo && !sg_hookedSendMsg && !sg_hookedSend) return @"Spotify socket hooks unavailable.";
        if (!sg_attempts) return @"No Spotify _spotify-connect multicast query observed yet.";
        return [NSString stringWithFormat:@"%lu query attempt(s). Last: %@", (unsigned long)sg_attempts, sg_lastAttempt];
    }
}

%ctor {
    sg_probeLock = [NSObject new];
    sg_hookedSendTo = SGRebindImport("sendto", probeSendTo, (void **)&sg_originalSendTo) && sg_originalSendTo;
    sg_hookedSendMsg = SGRebindImport("sendmsg", probeSendMsg, (void **)&sg_originalSendMsg) && sg_originalSendMsg;
    sg_hookedSend = SGRebindImport("send", probeSend, (void **)&sg_originalSend) && sg_originalSend;
}
