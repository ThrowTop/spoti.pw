// Personal builds disable usage, update checks/notices and certificate promotions.
// Compatibility functions remain for existing callers; they cannot submit requests.
#import <UIKit/UIKit.h>
#import "Settings/SGModPage.h"

extern NSString *const SGUpdateURL;   // empty in personal builds
extern NSString *const SGUpdateCheckedNotification;   // on the main thread, after a check ends either way

// One line of a release's changelog: what changed, under the heading Release Please put it under,
// and the commit it came from.
@interface SGUpdateChange : NSObject
@property (nonatomic, copy) NSString *kind;   // "Features", "Fixes", ... as the release names it
@property (nonatomic, copy) NSString *text;
@property (nonatomic, copy) NSString *url;    // the commit, nil for a line written by hand
@end

// One GitHub release, as the last check stored it.
@interface SGUpdateRelease : NSObject
@property (nonatomic, copy) NSString *version;   // without the tag's v
@property (nonatomic, copy) NSString *date;      // ISO 8601, as GitHub publishes it
@property (nonatomic, copy) NSString *url;       // the release page, where the .deb is
@property (nonatomic, copy) NSArray<SGUpdateChange *> *changes;
@end

NSArray<SGUpdateRelease *> *SGUpdateReleases(void);   // newest first, empty until a check lands
SGUpdateRelease *SGUpdateNewestRelease(void);
NSString *SGUpdateVersion(void);  // nil unless GitHub has a release newer than this build
BOOL SGUpdateIsNewer(NSString *version);   // whether that release is newer than the build running
NSString *SGUpdateStatus(void);
void SGCheckForUpdate(BOOL force);
UIViewController *SGUpdatePage(void);   // UpdatePage.m: the state and the changelog
UIViewController *SGLicensesPage(void); // Licenses.m: the mod's license and the third-party ones it ships

// Compatibility functions, disabled in personal builds regardless of stored preferences.
#define SGKeyUsage @"spotipw.usage"
NSData *SGUsageBody(void);       // always nil
BOOL SGUsageOwed(void);          // always NO
void SGUsageNoteAsked(void);     // no-op
#define SGKeyUpdateNotice @"spotifyglass.update.notice"
void SGWatchForUpdates(void);    // no-op
BOOL SGUpdateNoticeShown(void);  // always NO

// Whether the now playing card on the lock screen can open this build. It depends on the signature,
// not on the mod: iOS launches by the App ID of the application-identifier entitlement, so a build
// whose bundle id is not that App ID cannot be opened from the card. Signing.m says so once.
extern NSString *const SGSigningHelpURL;
NSString *SGSigningAppIdentifier(void);      // App ID without the team prefix, nil if unreadable
BOOL SGSigningOpensFromLockScreen(void);     // YES when unreadable, so a build that works stays quiet
SGModRow *SGSigningWarningRow(void);          // nil while the signature is sound
void SGCheckSigningOnce(void);
void SGShowSigningFixIfPending(void);   // the sheet the tour held back, if any

// Compatibility.m: a Spotify other than SGSupportedSpotifyVersion, or EeveeSpotify injected alongside.
// Each gets an alert once and a red row at the top of Mod Settings.
NSArray<SGModRow *> *SGCompatibilityWarningRows(void);   // empty when neither
void SGCheckCompatibilityOnce(void);

// Local signing information; certificate promotions and network requests are disabled.
NSString *SGCertificateKind(void);
NSDate *SGCertificateExpiry(void);
SGModRow *SGCertificateRow(void);    // always nil
void SGWatchForCertificate(void);   // no-op
BOOL SGCertificateOfferShown(void); // always NO
void SGShowCertificateSheet(NSDictionary *offer, UIImage *logo); // no-op

// Backup.m: the settings out to a JSON file through the share sheet, and back in from one, replacing
// what is set and restarting.
void SGExportSettings(void);
void SGImportSettings(void);

// AppIcon.m: the row that opens the list of app icons, nil in a build without them (scripts/app-icons.sh).
SGModRow *SGAppIconRow(void);

UIViewController *SGAboutPage(void);   // the Mod page
