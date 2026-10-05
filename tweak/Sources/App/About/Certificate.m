// Local signing information only. Certificate promotions and their requests are disabled.
#import "Core/SGCore.h"
#import "About.h"

static NSDictionary *profile(void) {
    static NSDictionary *read;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        NSString *path = [NSBundle.mainBundle pathForResource:@"embedded" ofType:@"mobileprovision"];
        NSData *data = path ? [NSData dataWithContentsOfFile:path] : nil;
        if (!data.length) return;
        // The plist sits as plain text inside the profile's CMS envelope.
        NSRange all = NSMakeRange(0, data.length);
        NSRange start = [data rangeOfData:[@"<?xml" dataUsingEncoding:NSASCIIStringEncoding] options:0 range:all];
        NSRange end = [data rangeOfData:[@"</plist>" dataUsingEncoding:NSASCIIStringEncoding] options:NSDataSearchBackwards range:all];
        if (start.location == NSNotFound || end.location == NSNotFound || end.location < start.location) return;
        NSData *plist = [data subdataWithRange:NSMakeRange(start.location, NSMaxRange(end) - start.location)];
        id parsed = [NSPropertyListSerialization propertyListWithData:plist options:0 format:NULL error:NULL];
        if ([parsed isKindOfClass:NSDictionary.class]) read = parsed;
    });
    return read;
}

static NSDate *dateIn(NSDictionary *info, NSString *key) {
    id value = info[key];
    return [value isKindOfClass:NSDate.class] ? value : nil;
}

NSDate *SGCertificateExpiry(void) {
    return dateIn(profile(), @"ExpirationDate");
}

NSString *SGCertificateKind(void) {
    NSDictionary *info = profile();
    if (!info) return @"none";
    if ([info[@"ProvisionsAllDevices"] boolValue]) return @"enterprise";
    NSDate *created = dateIn(info, @"CreationDate"), *expires = dateIn(info, @"ExpirationDate");
    if (!created || !expires) return nil;
    return [expires timeIntervalSinceDate:created] <= kFreeLongest ? @"free" : @"paid";
}

BOOL SGCertificateOfferShown(void) { return NO; }
SGModRow *SGCertificateRow(void) { return nil; }
void SGWatchForCertificate(void) {}
void SGShowCertificateSheet(NSDictionary *offer, UIImage *logo) {}
