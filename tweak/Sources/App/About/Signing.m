// Whether the lock screen can open this build at all. MediaRemote launches the now playing app by
// the App ID in its application-identifier entitlement, not by CFBundleIdentifier, so a build signed
// under a profile whose App ID is not the bundle id installs and plays but cannot be opened from the
// now playing card: iOS asks for a bundle that is not installed and offers the App Store instead.
// The signature decides this and nothing in the app can change it, so all the mod does is say so --
// once on the first launch under a signature, and from a red row at the top of Mod Settings for as
// long as it lasts. Both land on the same sheet, which names the bundle id to sign under and copies
// it, because that one string is the whole fix.
#import "Core/SGCore.h"
#import "Settings/SGPageStyle.h"
#import "About.h"
#import "App/Onboarding/Onboarding.h"
#import "Shared/ConnectDiscovery/DiscoveryProbe.h"
#import <dlfcn.h>
#import <errno.h>
#import <netinet/in.h>
#import <string.h>
#import <sys/socket.h>
#import <unistd.h>

NSString *const SGSigningHelpURL = @"https://github.com/skopevoj/spoti.pw#signing-it-yourself";

static NSString *const kWarned = @"spotifyglass.signing.warned";
static BOOL sg_fixPending;

static id SGSigningEntitlement(NSString *name) {
    void *security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_LAZY);
    if (!security) return nil;
    CFTypeRef (*createFromSelf)(CFAllocatorRef) = dlsym(security, "SecTaskCreateFromSelf");
    CFTypeRef (*copyValue)(CFTypeRef, CFStringRef, CFErrorRef *) = dlsym(security, "SecTaskCopyValueForEntitlement");
    if (!createFromSelf || !copyValue) return nil;
    CFTypeRef task = createFromSelf(NULL);
    if (!task) return nil;
    CFTypeRef value = copyValue(task, (__bridge CFStringRef)name, NULL);
    CFRelease(task);
    return value ? CFBridgingRelease(value) : nil;
}

// SecTaskCopyValueForEntitlement is not in the iOS SDK, so it is resolved at runtime like the rest
// of the private API the mod uses. A build that cannot read an entitlement returns nil.
NSString *SGSigningAppIdentifier(void) {
    static NSString *cached;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        id value = SGSigningEntitlement(@"application-identifier");
        if ([value isKindOfClass:NSString.class]) {
            NSString *identifier = value;
            NSRange dot = [identifier rangeOfString:@"."];   // drop the team prefix
            cached = dot.location == NSNotFound ? [identifier copy]
                                               : [identifier substringFromIndex:dot.location + 1];
        }
    });
    return cached;
}

// The entitlement plist can claim multicast even when the sideloader's profile doesn't authorize it.
// Query the running task and exercise the kernel's multicast join/send paths on demand.
NSString *SGMulticastDiagnostic(void) {
    id entitlement = SGSigningEntitlement(@"com.apple.developer.networking.multicast");
    NSString *claim = [entitlement isKindOfClass:NSNumber.class]
        ? ([entitlement boolValue] ? @"true" : @"false")
        : (entitlement ? [entitlement description] : @"unavailable");
    NSString *appID = SGSigningAppIdentifier() ?: @"unavailable";

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0) {
        SGLog(@"multicast diagnostic: appID=%@ entitlement=%@ socket=failed errno=%d", appID, claim, errno);
        return [NSString stringWithFormat:@"App ID: %@\nRuntime multicast entitlement: %@\nSocket: failed (errno %d: %s)",
                appID, claim, errno, strerror(errno)];
    }

    struct ip_mreq membership = {0};
    membership.imr_multiaddr.s_addr = htonl(0xE00000FB); // 224.0.0.251 (mDNS)
    membership.imr_interface.s_addr = htonl(INADDR_ANY);
    int joinResult = setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &membership, sizeof(membership));
    int joinError = joinResult == 0 ? 0 : errno;

    // A harmless PTR lookup for Cast receivers. This validates outbound multicast too.
    static const unsigned char query[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0B, '_', 'g', 'o', 'o', 'g', 'l', 'e', 'c', 'a', 's', 't',
        0x04, '_', 't', 'c', 'p', 0x05, 'l', 'o', 'c', 'a', 'l', 0x00,
        0x00, 0x0C, 0x00, 0x01
    };
    struct sockaddr_in target = {0};
    target.sin_family = AF_INET;
    target.sin_port = htons(5353);
    target.sin_addr.s_addr = htonl(0xE00000FB);
    ssize_t sent = sendto(fd, query, sizeof(query), 0, (struct sockaddr *)&target, sizeof(target));
    int sendError = sent < 0 ? errno : 0;
    if (joinResult == 0) setsockopt(fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &membership, sizeof(membership));
    close(fd);

    NSString *join = joinResult == 0 ? @"ok" : [NSString stringWithFormat:@"failed (errno %d: %s)", joinError, strerror(joinError)];
    NSString *send = sent == sizeof(query) ? @"ok" : [NSString stringWithFormat:@"failed (errno %d: %s)", sendError, strerror(sendError)];
    SGLog(@"multicast diagnostic: appID=%@ entitlement=%@ join=%@ send=%@", appID, claim, join, send);
    return [NSString stringWithFormat:@"App ID: %@\nRuntime multicast entitlement: %@\nJoin mDNS group: %@\nSend Cast discovery query: %@",
            appID, claim, join, send];
}

void SGShowMulticastDiagnostic(void) {
    NSString *result = SGMulticastDiagnostic();
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Local network diagnostic"
                                                                   message:result
                                                            preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"Copy result" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UIPasteboard.generalPasteboard.string = result;
    }]];
    [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:nil]];
    [SGTopController() presentViewController:alert animated:YES completion:nil];
}

// Apple can browse a named Bonjour service without the broad multicast entitlement. Compare this
// result with Spotify's Connect sheet to distinguish LAN visibility from Spotify's own discovery.
@interface SGConnectBonjourProbe : NSObject <NSNetServiceBrowserDelegate>
@property (nonatomic, strong) NSNetServiceBrowser *browser;
@property (nonatomic, strong) NSMutableOrderedSet<NSString *> *names;
@property (nonatomic, strong) UIAlertController *alert;
@property (nonatomic, strong) UIAlertAction *resultAction;
@property (nonatomic, copy) NSString *result;
@property (nonatomic, copy) NSString *error;
@property (nonatomic, assign) BOOL finished;
- (void)start;
- (void)stop;
@end

static SGConnectBonjourProbe *sgConnectBonjourProbe;

@implementation SGConnectBonjourProbe

- (void)start {
    self.names = [NSMutableOrderedSet orderedSet];
    self.browser = [NSNetServiceBrowser new];
    self.browser.delegate = self;
    [self.browser searchForServicesOfType:@"_spotify-connect._tcp." inDomain:@"local."];

    __weak typeof(self) weakSelf = self;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(7 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        [weakSelf finish];
    });
}

- (void)stop {
    self.finished = YES;
    [self.browser stop];
    self.browser.delegate = nil;
    self.browser = nil;
    if (sgConnectBonjourProbe == self) sgConnectBonjourProbe = nil;
}

- (void)finish {
    if (self.finished) return;
    NSArray<NSString *> *names = [self.names.array sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    NSString *detail = names.count ? [names componentsJoinedByString:@"\n"] : @"No Spotify Connect services found.";
    if (self.error) detail = [detail stringByAppendingFormat:@"\nBrowser error: %@", self.error];
    self.result = [NSString stringWithFormat:@"Bonjour _spotify-connect._tcp:\n%@\n\nSpotify's own mDNS:\n%@",
                  detail, SGConnectRawDiscoverySnapshot()];
    SGLog(@"Connect Bonjour diagnostic: %@", self.result);
    self.alert.message = self.result;
    self.resultAction.enabled = YES;
    [self stop];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)moreComing {
    [self.names addObject:service.name];
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didNotSearch:(NSDictionary<NSString *, NSNumber *> *)errorDict {
    self.error = errorDict.description;
    [self finish];
}

@end

void SGShowConnectBonjourDiagnostic(void) {
    UIViewController *top = SGTopController();
    if (!top) return;
    [sgConnectBonjourProbe stop];
    SGConnectBonjourProbe *probe = [SGConnectBonjourProbe new];
    sgConnectBonjourProbe = probe;
    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Spotify Connect discovery"
                                                                   message:@"Looking for nearby receivers for seven seconds…"
                                                            preferredStyle:UIAlertControllerStyleAlert];
    probe.alert = alert;
    __weak SGConnectBonjourProbe *weakProbe = probe;
    __weak UIAlertController *weakAlert = alert;
    UIAlertAction *copy = [UIAlertAction actionWithTitle:@"Copy result" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UIPasteboard.generalPasteboard.string = weakAlert.message;
    }];
    copy.enabled = NO;
    probe.resultAction = copy;
    [alert addAction:copy];
    [alert addAction:[UIAlertAction actionWithTitle:@"Done" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
        [weakProbe stop];
    }]];
    [top presentViewController:alert animated:YES completion:^{
        [probe start];
    }];
}

// Unreadable counts as fine: a guess here would cry wolf at a build that works.
BOOL SGSigningOpensFromLockScreen(void) {
    NSString *appID = SGSigningAppIdentifier();
    return !appID || [appID isEqualToString:NSBundle.mainBundle.bundleIdentifier];
}

// The fix is one string, so the sheet leads with it and Copy is the first action: whoever reads this
// is on their way back to Feather to paste it into the identifier field.
static void showFix(void) {
    NSString *appID = SGSigningAppIdentifier();
    NSString *bundleID = NSBundle.mainBundle.bundleIdentifier ?: @"?";
    UIViewController *top = SGTopController();
    if (!appID || !top) return;
    NSString *message = [NSString stringWithFormat:
        @"Sign Spotify again with the bundle id set to\n\n%@\n\n"
        @"In Feather that is the Identifier field; leave PPQ protection off, it appends a random "
        @"string and breaks this again.\n\n"
        @"Why: this build is installed as %@ but signed under the App ID %@. iOS opens the now "
        @"playing card by the App ID, so it asks for an app that is not there. Nothing else in the "
        @"mod is affected.", appID, bundleID, appID];
    UIAlertController *sheet = [UIAlertController alertControllerWithTitle:@"The lock screen cannot open Spotify"
                                                                  message:message
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Copy the bundle id" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        UIPasteboard.generalPasteboard.string = appID;
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Read more" style:UIAlertActionStyleDefault handler:^(UIAlertAction *action) {
        SGOpenURL(SGSigningHelpURL);
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
    [top presentViewController:sheet animated:YES completion:nil];
}

// nil while the signature is sound, which is what keeps the row out of Mod Settings entirely.
SGModRow *SGSigningWarningRow(void) {
    if (SGSigningOpensFromLockScreen()) return nil;
    return SGWarningRow(@"The lock screen cannot open Spotify",
                        @"Tap for the fix",
                        ^{ showFix(); });
}

// Said once per signature: re-signing under a different App ID is a new mistake and says so again,
// but a build that is simply left broken does not nag on every launch. The row stays either way.
void SGCheckSigningOnce(void) {
    if (SGSigningOpensFromLockScreen()) return;
    NSString *appID = SGSigningAppIdentifier();
    NSUserDefaults *store = NSUserDefaults.standardUserDefaults;
    SGLog(@"signing: installed as %@ but signed under %@; the now playing card cannot open this build",
          NSBundle.mainBundle.bundleIdentifier, appID);
    if ([[store stringForKey:kWarned] isEqualToString:appID]) return;
    [store setObject:appID forKey:kWarned];

    // The first activation, plus a moment for Spotify's own start-up screens to get out of the way.
    __block id token = [NSNotificationCenter.defaultCenter addObserverForName:UIApplicationDidBecomeActiveNotification
                                                                      object:nil
                                                                       queue:nil
                                                                  usingBlock:^(NSNotification *note) {
        [NSNotificationCenter.defaultCenter removeObserver:token];
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            // The welcome tour has the screen; it shows the fix when it goes.
            if (SGOnboardingShowing()) sg_fixPending = YES;
            else showFix();
        });
    }];
}

void SGShowSigningFixIfPending(void) {
    if (!sg_fixPending) return;
    sg_fixPending = NO;
    showFix();
}
