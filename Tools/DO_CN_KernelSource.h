//
//  DO_CN_KernelSource.h
//  Dopamine CN hybrid kernel source
//
//  Fully inline implementation: this header is #import'ed by
//  DOEnvironmentManager.m only. No new compile source, no new linked
//  framework and no .xcodeproj / pbxproj edit is required.
//
//  Hybrid kernel acquisition (three layers)
//  ---------------------------------------
//  L1  Build-time index (main path, mainland-China friendly).
//      All AppleDB metadata and every IPSW central directory were resolved on
//      the GitHub Actions runner and shipped as KernelIndex.plist in the app
//      bundle. This file never contacts api.appledb.dev. For a hit it issues
//      one HTTP Range request per image against updates.cdn-apple.com (or a
//      user supplied mirror), inflates raw deflate, verifies CRC32 / SHA-256
//      and atomically writes Documents/kernelcache, Documents/sptm.im4p and
//      Documents/txm.im4p - exactly the paths -accessibleSPTMPath /
//      -accessibleTXMPath look up.
//
//  L2  Hardened runtime resolve (index miss / new firmware).
//      Tools/apply_hardening.py replaces the upstream libgrabkernel2.a and
//      libpartial.a with hardened builds. grab_images() then walks every
//      AppleDB firmware candidate, retries each three times, verifies the
//      BuildManifest digest and stages all three images. This keeps the
//      "no prebuilt index needed" property. It may contact api.appledb.dev,
//      so it is only a fallback - L1 is what makes a normal signature work
//      without a proxy.
//
//  L3  Upstream failure path. No multi-GB IPSW download is attempted.
//
//  Request hardening (shared by L1 and derived from L2's partial-zip work):
//  Accept-Encoding: identity, Safari UA, If-Range/ETag, 200-response slicing
//  with a hard size cap, explicit short-read rejection, 120 s / 900 s
//  timeouts and three attempts per candidate.
//
//  Schema 2 indexes one entry per <hw.machine>|<kern.osversion> for every
//  iPhone/iPad/iPod and every firmware Dopamine supports, so any supported
//  device installed with a normal (non-TrollStore) signature is covered.
//

#ifndef DO_CN_KernelSource_h
#define DO_CN_KernelSource_h

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>
// Dopamine already links libz.tbd / libcompression.tbd, so raw inflate needs
// no project file change (BaseBin/dopamine/Makefile additionally gets -lz).
#import <zlib.h>

// schema 1 = single-target index with SHA-256 digests (offline/exact builds)
// schema 2 = full-coverage index with ZIP CRC32 digests (no payload download
//            at build time, thousands of <device>|<build> entries)
#define DOCN_INDEX_SCHEMA 2
#define DOCN_HTTP_TIMEOUT 120.0
#define DOCN_HTTP_RESOURCE_TIMEOUT 900.0
#define DOCN_MAX_ATTEMPTS 3
// A CDN that ignores Range may stream the whole IPSW. Never buffer more than
// this in memory; slice small accidental 200 responses instead.
#define DOCN_MAX_ACCIDENTAL_FULL_RESPONSE (128ULL * 1024 * 1024)

static NSString *DOCNStringForSysctl(const char *name) {
    size_t size = 0;
    if (sysctlbyname(name, NULL, &size, NULL, 0) != 0 || size == 0) return nil;
    char *buffer = (char *)calloc(1, size);
    if (!buffer) return nil;
    if (sysctlbyname(name, buffer, &size, NULL, 0) != 0) {
        free(buffer);
        return nil;
    }
    NSString *value = [NSString stringWithUTF8String:buffer];
    free(buffer);
    return value;
}

static NSString *DOCNBundlePath(NSString *name) {
    return [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:name];
}

static NSDictionary *DOCNLoadIndex(NSString *documentsDir) {
    // Advanced users can drop a KernelIndexOverride.plist into Documents to
    // point at a mainland mirror without rebuilding the IPA.
    NSString *override = [documentsDir stringByAppendingPathComponent:@"KernelIndexOverride.plist"];
    NSDictionary *index = [NSDictionary dictionaryWithContentsOfFile:override];
    if (!index) {
        index = [NSDictionary dictionaryWithContentsOfFile:DOCNBundlePath(@"KernelIndex.plist")];
    }
    if (![index isKindOfClass:NSDictionary.class]) return nil;
    NSNumber *schema = index[@"schema"];
    if (![schema isKindOfClass:NSNumber.class] ||
        (schema.integerValue != 1 && schema.integerValue != DOCN_INDEX_SCHEMA)) {
        NSLog(@"[CNKernel] index schema rejected: %@", schema);
        return nil;
    }
    if (![index[@"entries"] isKindOfClass:NSDictionary.class]) return nil;
    return index;
}

static NSString *DOCNSHA256(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *out = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        [out appendFormat:@"%02x", digest[i]];
    }
    return out;
}

// A full-coverage index cannot carry SHA-256: computing it would mean
// downloading every 17 MB kernelcache at build time. ZIP central directories
// already hold the CRC32 of the *uncompressed* member, which is exactly what
// the device has after inflating. libz is already linked by the project.
static uint32_t DOCNCRC32(NSData *data) {
    uLong crc = crc32(0L, Z_NULL, 0);
    return (uint32_t)crc32(crc, data.bytes, (uInt)data.length);
}

static BOOL DOCNVerifyImage(NSData *data, NSDictionary *info) {
    if (!data.length) return NO;
    NSString *hash = info[@"sha256"];                 // schema 1
    if ([hash isKindOfClass:NSString.class] && hash.length) {
        return [DOCNSHA256(data) isEqualToString:hash];
    }
    NSNumber *crc = info[@"crc32"];                    // schema 2
    if ([crc isKindOfClass:NSNumber.class]) {
        return DOCNCRC32(data) == (uint32_t)crc.unsignedIntValue;
    }
    return YES;  // legacy entry with no digest
}

// ETag of the first response per URL; If-Range keeps subsequent Range requests
// pinned to the same IPSW representation so a CDN edge cannot mix versions.
static NSMutableDictionary<NSString *, NSString *> *DOCNETagCache(void) {
    static NSMutableDictionary *cache = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        cache = [NSMutableDictionary dictionary];
    });
    return cache;
}

// Synchronous NSURLSession data task. The completion handler runs on the
// session's own delegate queue, so waiting on a semaphore here is safe.
static NSData *DOCNHTTPFetch(NSURL *url, uint64_t start, uint64_t length, NSTimeInterval timeout) {
    if (!url) return nil;
    NSString *cacheKey = url.absoluteString;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                          cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                      timeoutInterval:timeout];
    // gzip/zstd transport encoding would shift every byte offset we computed
    // from the ZIP central directory. Force identity on every hop.
    [request setValue:@"identity" forHTTPHeaderField:@"Accept-Encoding"];
    [request setValue:@"Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_16 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1 DopamineCNKernel/2.0" forHTTPHeaderField:@"User-Agent"];
    [request setValue:@"*/*" forHTTPHeaderField:@"Accept"];
    [request setValue:@"zh-CN,zh;q=0.9,en;q=0.8" forHTTPHeaderField:@"Accept-Language"];
    [request setValue:@"keep-alive" forHTTPHeaderField:@"Connection"];
    if (length > 0) {
        [request setValue:[NSString stringWithFormat:@"bytes=%llu-%llu", start, start + length - 1]
       forHTTPHeaderField:@"Range"];
        NSString *knownETag = nil;
        @synchronized (DOCNETagCache()) {
            knownETag = DOCNETagCache()[cacheKey];
        }
        if (knownETag.length) {
            [request setValue:knownETag forHTTPHeaderField:@"If-Range"];
        }
    }

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *payload = nil;
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.timeoutIntervalForRequest = timeout;
    configuration.timeoutIntervalForResource = DOCN_HTTP_RESOURCE_TIMEOUT;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSHTTPURLResponse *http = [response isKindOfClass:NSHTTPURLResponse.class]
                ? (NSHTTPURLResponse *)response : nil;
            NSInteger status = http ? http.statusCode : 0;
            NSString *etag = [http valueForHTTPHeaderField:@"ETag"] ?: http.allHeaderFields[@"ETag"];
            if (etag.length) {
                @synchronized (DOCNETagCache()) {
                    DOCNETagCache()[cacheKey] = etag;
                }
            }
            if (!error && length == 0 && (status == 200 || status == 206) && data.length > 0) {
                // Whole-file mirror download.
                payload = data;
            }
            else if (!error && length > 0 && status == 206 && data.length == length) {
                // Exact partial content.
                payload = data;
            }
            else if (!error && length > 0 && status == 200 &&
                     data.length >= start + length &&
                     data.length <= DOCN_MAX_ACCIDENTAL_FULL_RESPONSE) {
                // Some caching layers ignore Range and return the whole object.
                // Slice back to our window, but refuse multi-GB responses.
                payload = [data subdataWithRange:NSMakeRange((NSUInteger)start, (NSUInteger)length)];
                NSLog(@"[CNKernel] server ignored Range, sliced %llu bytes from 200 response", length);
            }
            else {
                NSLog(@"[CNKernel] request failed status=%ld bytes=%lu wanted=%llu error=%@",
                      (long)status, (unsigned long)data.length, length,
                      error.localizedDescription);
            }
            dispatch_semaphore_signal(semaphore);
        }];
    [task resume];
    dispatch_semaphore_wait(semaphore,
                            dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 10) * NSEC_PER_SEC)));
    [session invalidateAndCancel];
    return payload;
}

// IPSW members are raw-deflate (compression method 8), so the Range bytes
// must be inflated before they become a usable kernelcache / im4p.
static NSData *DOCNInflateRaw(NSData *data, uint64_t expectedSize) {
    if (expectedSize == 0 || expectedSize > 512ULL * 1024 * 1024) return nil;
    NSMutableData *out = [NSMutableData dataWithLength:(NSUInteger)expectedSize];
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)data.bytes;
    stream.avail_in = (uInt)data.length;
    stream.next_out = (Bytef *)out.mutableBytes;
    stream.avail_out = (uInt)expectedSize;
    if (inflateInit2(&stream, -MAX_WBITS) != Z_OK) return nil;
    int status = inflate(&stream, Z_FINISH);
    uint64_t produced = stream.total_out;
    inflateEnd(&stream);
    if (status != Z_STREAM_END || produced != expectedSize) {
        NSLog(@"[CNKernel] inflate failed status=%d produced=%llu expected=%llu",
              status, produced, expectedSize);
        return nil;
    }
    return out;
}

static BOOL DOCNWriteAtomically(NSData *data, NSString *destination) {
    NSString *temporary = [destination stringByAppendingFormat:@".cn-%@", NSUUID.UUID.UUIDString];
    if (![data writeToFile:temporary atomically:YES]) return NO;
    if (rename(temporary.fileSystemRepresentation, destination.fileSystemRepresentation) != 0) {
        [[NSFileManager defaultManager] removeItemAtPath:temporary error:nil];
        return NO;
    }
    return YES;
}

// Download one logical image. Every candidate is attempted up to
// DOCN_MAX_ATTEMPTS times; short reads and checksum mismatches are retried.
static NSData *DOCNFetchImage(NSDictionary *index, NSDictionary *entry,
                              NSString *slot, NSArray<NSString *> *firmwareURLs) {
    NSDictionary *info = entry[slot];
    if (![info isKindOfClass:NSDictionary.class]) return nil;
    NSNumber *compression = info[@"compression"];

    // Whole-file mirrors take priority: they work even for deflated ZIP
    // members and are the easiest way to point at a mainland CDN/OSS bucket.
    NSDictionary *direct = entry[@"directURLs"] ?: index[@"directURLs"];
    NSArray *directURLs = [direct[slot] isKindOfClass:NSArray.class] ? direct[slot] : nil;
    for (NSString *candidate in directURLs) {
        NSURL *url = [NSURL URLWithString:candidate];
        for (int attempt = 0; attempt < DOCN_MAX_ATTEMPTS; attempt++) {
            if (attempt) {
                NSLog(@"[CNKernel] Retrying mirror download (attempt %d/%d)",
                      attempt + 1, DOCN_MAX_ATTEMPTS);
                sleep(1);
            }
            NSData *data = DOCNHTTPFetch(url, 0, 0, DOCN_HTTP_TIMEOUT);
            if (!data.length || !DOCNVerifyImage(data, info)) {
                NSLog(@"[CNKernel] %@ direct mirror empty or checksum mismatch", slot);
                continue;
            }
            return data;
        }
    }

    NSInteger method = compression.integerValue;
    if (method != 0 && method != 8) {
        NSLog(@"[CNKernel] %@ uses unsupported zip method %ld", slot, (long)method);
        return nil;
    }
    NSNumber *offset = info[@"offset"];
    NSNumber *length = info[@"length"];
    if (![offset isKindOfClass:NSNumber.class] || ![length isKindOfClass:NSNumber.class]
        || length.unsignedLongLongValue == 0) {
        return nil;
    }
    uint64_t start = offset.unsignedLongLongValue;
    uint64_t count = length.unsignedLongLongValue;

    for (NSString *candidate in firmwareURLs) {
        NSURL *url = [NSURL URLWithString:candidate];
        for (int attempt = 0; attempt < DOCN_MAX_ATTEMPTS; attempt++) {
            if (attempt) {
                NSLog(@"[CNKernel] Retrying range download (attempt %d/%d)",
                      attempt + 1, DOCN_MAX_ATTEMPTS);
                sleep(1);
            }
            NSData *data = DOCNHTTPFetch(url, start, count, DOCN_HTTP_TIMEOUT);
            if (data.length != count) {
                NSLog(@"[CNKernel] %@ short read (%lu/%llu bytes)", slot,
                      (unsigned long)data.length, count);
                continue;
            }
            if (method == 8) {
                NSNumber *rawSize = info[@"size"] ?: info[@"uncompressedSize"];
                data = DOCNInflateRaw(data, rawSize.unsignedLongLongValue);
                if (!data) continue;
            }
            if (!DOCNVerifyImage(data, info)) {
                NSLog(@"[CNKernel] %@ checksum mismatch from %@", slot, candidate);
                continue;
            }
            NSLog(@"[CNKernel] %@ ready (%lu bytes) from %@", slot,
                  (unsigned long)data.length, url.host);
            return data;
        }
    }
    return nil;
}

static BOOL DOCNTryIndexDownload(NSString *documentsDir) {
    NSDictionary *index = DOCNLoadIndex(documentsDir);
    if (!index) return NO;

    NSString *device = DOCNStringForSysctl("hw.machine");
    NSString *build = DOCNStringForSysctl("kern.osversion");
    if (!device.length || !build.length) return NO;
    NSString *key = [NSString stringWithFormat:@"%@|%@", device, build];
    NSDictionary *entry = index[@"entries"][key];
    if (![entry isKindOfClass:NSDictionary.class]) {
        NSLog(@"[CNKernel] no index entry for %@; falling back to L2", key);
        return NO;
    }
    NSArray<NSString *> *firmwareURLs = entry[@"firmwareURLs"];
    if (![firmwareURLs isKindOfClass:NSArray.class] || firmwareURLs.count == 0) return NO;
    NSLog(@"[CNKernel] L1 index hit %@ (%lu mirror(s))", key, (unsigned long)firmwareURLs.count);

    NSDictionary<NSString *, NSString *> *destinations = @{
        @"kernel" : @"kernelcache",
        @"sptm"   : @"sptm.im4p",
        @"txm"    : @"txm.im4p",
    };
    BOOL ok = YES;
    for (NSString *slot in @[@"kernel", @"sptm", @"txm"]) {
        if (![entry[slot] isKindOfClass:NSDictionary.class]) continue;  // optional images
        NSString *destination = [documentsDir stringByAppendingPathComponent:destinations[slot]];
        if ([[NSFileManager defaultManager] fileExistsAtPath:destination]) continue;
        NSData *data = DOCNFetchImage(index, entry, slot, firmwareURLs);
        if (!data || !DOCNWriteAtomically(data, destination)) {
            NSLog(@"[CNKernel] failed to materialize %@; falling back to L2", slot);
            ok = NO;
            break;
        }
    }
    if (!ok) {
        // Avoid leaving a half-populated Documents directory behind.
        for (NSString *name in destinations.allValues) {
            [[NSFileManager defaultManager]
                removeItemAtPath:[documentsDir stringByAppendingPathComponent:name] error:nil];
        }
    }
    return ok;
}

#endif /* DO_CN_KernelSource_h */
