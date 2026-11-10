//
//  DO_CN_KernelSource.h
//  Dopamine-roothide CN kernel source
//
//  Fully inline implementation: this header is #import'ed by
//  DOEnvironmentManager.m only. No new compile source, no new linked
//  framework and no .xcodeproj / pbxproj edit is required.
//
//  Runtime data flow
//  -----------------
//  Upstream libgrabkernel2 first downloads a ~72 MB metadata blob from
//  api.appledb.dev, which is unreliable on mainland China networks. This
//  helper never contacts that host. All metadata was resolved on the GitHub
//  Actions runner and shipped as KernelIndex.plist in the app bundle. At
//  runtime it only issues HTTP Range requests against updates.cdn-apple.com
//  (or a user supplied mirror), verifies SHA-256 and atomically writes
//  Documents/kernelcache, Documents/sptm.im4p and Documents/txm.im4p, which
//  are exactly the paths -accessibleSPTMPath / -accessibleTXMPath look up.
//
//  If anything misses or fails, it returns NO and the original
//  grab_images() path remains the fallback.
//

#ifndef DO_CN_KernelSource_h
#define DO_CN_KernelSource_h

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import <string.h>
#import <sys/sysctl.h>
#import <unistd.h>
// Dopamine-roothide already links libz.tbd / libcompression.tbd, so raw
// inflate needs no project file change.
#import <zlib.h>

#define DOCN_INDEX_SCHEMA 1
#define DOCN_HTTP_TIMEOUT 90.0

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
    if (![schema isKindOfClass:NSNumber.class] || schema.integerValue != DOCN_INDEX_SCHEMA) {
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

// Synchronous NSURLSession data task. The completion handler always runs on
// the session's own delegate queue, so waiting on a semaphore here is safe.
static NSData *DOCNHTTPFetch(NSURL *url, uint64_t start, uint64_t length, NSTimeInterval timeout) {
    if (!url) return nil;
    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:url
                                                          cachePolicy:NSURLRequestReloadIgnoringLocalCacheData
                                                      timeoutInterval:timeout];
    if (length > 0) {
        [request setValue:[NSString stringWithFormat:@"bytes=%llu-%llu", start, start + length - 1]
       forHTTPHeaderField:@"Range"];
    }
    [request setValue:@"DopamineCNKernel/1.0" forHTTPHeaderField:@"User-Agent"];

    dispatch_semaphore_t semaphore = dispatch_semaphore_create(0);
    __block NSData *payload = nil;
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    configuration.timeoutIntervalForRequest = timeout;
    configuration.timeoutIntervalForResource = timeout * 3;
    NSURLSession *session = [NSURLSession sessionWithConfiguration:configuration];
    NSURLSessionDataTask *task = [session dataTaskWithRequest:request
        completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
            NSInteger status = [response isKindOfClass:NSHTTPURLResponse.class]
                ? [(NSHTTPURLResponse *)response statusCode] : 0;
            if (!error && length == 0 && status == 200 && data.length > 0) {
                // Whole-file mirror download.
                payload = data;
            }
            else if (!error && length > 0 && status == 206 && data.length == length) {
                // A 200 here would mean the server ignored Range and streamed
                // the entire multi-GB IPSW; reject it instead of slicing.
                payload = data;
            }
            else {
                NSLog(@"[CNKernel] request failed status=%ld error=%@", (long)status, error.localizedDescription);
            }
            dispatch_semaphore_signal(semaphore);
        }];
    [task resume];
    dispatch_semaphore_wait(semaphore,
                            dispatch_time(DISPATCH_TIME_NOW, (int64_t)((timeout + 5) * NSEC_PER_SEC)));
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

// Download one logical image. Returns nil on failure.
static NSData *DOCNFetchImage(NSDictionary *index, NSDictionary *entry,
                              NSString *slot, NSArray<NSString *> *firmwareURLs) {
    NSDictionary *info = entry[slot];
    if (![info isKindOfClass:NSDictionary.class]) return nil;
    NSString *expectedHash = info[@"sha256"];
    NSNumber *compression = info[@"compression"];

    // Whole-file mirrors take priority: they work even for deflated ZIP
    // members and are the easiest way to point at a mainland CDN/OSS bucket.
    NSDictionary *direct = entry[@"directURLs"] ?: index[@"directURLs"];
    NSArray *directURLs = [direct[slot] isKindOfClass:NSArray.class] ? direct[slot] : nil;
    for (NSString *candidate in directURLs) {
        NSData *data = DOCNHTTPFetch([NSURL URLWithString:candidate], 0, 0, DOCN_HTTP_TIMEOUT);
        if (!data.length) continue;
        if (expectedHash.length && ![DOCNSHA256(data) isEqualToString:expectedHash]) {
            NSLog(@"[CNKernel] %@ direct mirror hash mismatch", slot);
            continue;
        }
        return data;
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
        NSData *data = DOCNHTTPFetch([NSURL URLWithString:candidate], start, count,
                                    DOCN_HTTP_TIMEOUT);
        if (data.length != count) continue;
        if (method == 8) {
            NSNumber *rawSize = info[@"size"] ?: info[@"uncompressedSize"];
            data = DOCNInflateRaw(data, rawSize.unsignedLongLongValue);
            if (!data) continue;
        }
        if (expectedHash.length && ![DOCNSHA256(data) isEqualToString:expectedHash]) {
            NSLog(@"[CNKernel] %@ hash mismatch from %@", slot, candidate);
            continue;
        }
        NSLog(@"[CNKernel] %@ ready (%lu bytes) from %@", slot,
              (unsigned long)data.length, [NSURL URLWithString:candidate].host);
        return data;
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
        NSLog(@"[CNKernel] no index entry for %@; falling back", key);
        return NO;
    }
    NSArray<NSString *> *firmwareURLs = entry[@"firmwareURLs"];
    if (![firmwareURLs isKindOfClass:NSArray.class] || firmwareURLs.count == 0) return NO;
    NSLog(@"[CNKernel] index hit %@ (%lu mirror(s))", key, (unsigned long)firmwareURLs.count);

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
            NSLog(@"[CNKernel] failed to materialize %@", slot);
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
