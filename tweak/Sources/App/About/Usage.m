// Personal builds never collect or submit installation usage data.
#import "About.h"

NSData *SGUsageBody(void) { return nil; }
BOOL SGUsageOwed(void) { return NO; }
void SGUsageNoteAsked(void) {}
