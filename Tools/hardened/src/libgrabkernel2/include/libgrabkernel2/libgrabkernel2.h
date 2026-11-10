//
//  libgrabkernel2.h
//  libgrabkernel2
//
//  Created by Alfie on 14/02/2024.
//
//  Merged header:
//   - Relaxin's verified range-download API (candidate walk, retries, digest)
//   - Dopamine's grab_images() API that stages kernelcache + SPTM + TXM
//

#ifndef grabkernel_h
#define grabkernel_h

#include <Foundation/Foundation.h>

// Returns the set of firmware links for the target, in preference order, as
// @{@"url": NSString, @"ota": @(BOOL)}. Defined in appledb.m.
NSArray<NSDictionary *> *getFirmwareURLCandidatesFor(NSString *osStr,
                                                     NSString *build,
                                                     NSString *modelIdentifier,
                                                     NSError **error);
NSArray<NSDictionary *> *getFirmwareURLCandidates(NSError **error);
NSString *getFirmwareURLFor(NSString *osStr, NSString *build,
                            NSString *modelIdentifier, bool *isOTA);
NSString *getFirmwareURL(bool *isOTA);
NSString *getOsStr(void);
NSString *getBuild(void);
NSString *getModelIdentifier(void);
NSString *getBoardconfig(void);

// ---------------------------------------------------------------------------
// image staging (Dopamine)
// ---------------------------------------------------------------------------

// Download the kernelcache, SPTM and TXM for the current device into outDir.
// SPTM/TXM are optional; SoCs that do not ship them succeed with kernelcache
// only.
bool grab_images(NSString *outDir);
bool grab_images_for(NSString *osStr, NSString *build,
                     NSString *modelIdentifier, NSString *boardConfig,
                     NSString *outDir);

// ---------------------------------------------------------------------------
// range download primitives (Relaxin)
// ---------------------------------------------------------------------------

bool download_kernelcache_for(NSString *boardconfig, NSString *zipURL,
                              bool isOTA, NSString *outPath);
bool download_kernelcache(NSString *zipURL, bool isOTA, NSString *outPath);
bool download_images(NSString *zipURL, bool isOTA, NSString *outDir);
bool download_images_for(NSString *boardconfig, NSString *zipURL,
                         bool isOTA, NSString *outDir);

// ---------------------------------------------------------------------------
// kernelcache acquisition
// ---------------------------------------------------------------------------

bool grab_kernelcache(NSString *outPath);
bool grab_kernelcache_for(NSString *osStr, NSString *build,
                          NSString *modelIdentifier, NSString *boardconfig,
                          NSString *outPath);
bool grab_kernelcache_for_with_error(NSString *osStr, NSString *build,
                                     NSString *modelIdentifier,
                                     NSString *boardconfig,
                                     NSString *outPath, NSError **error);
bool grab_kernelcache_for_with_digest(NSString *osStr, NSString *build,
                                      NSString *modelIdentifier,
                                      NSString *boardconfig,
                                      NSString *outPath,
                                      NSData **expectedDigest,
                                      NSError **error);
bool verify_kernelcache_digest(NSString *path, NSData *expectedDigest,
                               NSError **error);

// Uses details of the current device, but allows an override of the build
bool grab_kernelcache_for_build_number(NSString *build, NSString *outPath);

// libgrabkernel compatibility shim
// Note that research kernel grabbing is not currently supported
int grabkernel(char *downloadPath, int isResearchKernel);

#endif /* grabkernel_h */
