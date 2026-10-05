// Updates are installed through the custom-kit workflow. No server is contacted, including when
// a stale settings page or stored preference tries to request a manual check.
#import "About.h"

NSString *const SGUpdateURL = @"";
NSString *const SGUpdateCheckedNotification = @"spotifyglass.update.checked.notification";

@implementation SGUpdateChange
@end
@implementation SGUpdateRelease
@end

NSArray<SGUpdateRelease *> *SGUpdateReleases(void) { return @[]; }
SGUpdateRelease *SGUpdateNewestRelease(void) { return nil; }
NSString *SGUpdateVersion(void) { return nil; }
BOOL SGUpdateIsNewer(NSString *version) { return NO; }
NSString *SGUpdateStatus(void) { return @"disabled in this custom build"; }
void SGCheckForUpdate(BOOL force) {}
