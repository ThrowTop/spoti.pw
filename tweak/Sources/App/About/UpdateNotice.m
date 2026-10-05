// No foreground observer or automatic update notice in personal builds.
#import "About.h"

BOOL SGUpdateNoticeShown(void) { return NO; }
void SGWatchForUpdates(void) {}
