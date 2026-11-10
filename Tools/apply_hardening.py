#!/usr/bin/env python3
"""
Apply the hardened download layer to a Dopamine checkout.

This is step 2 of the hybrid kernel acquisition chain:

  L1  KernelIndex.plist (resolved on the CI runner) -> one Range per image
      against updates.cdn-apple.com. No api.appledb.dev access on device.
  L2  Hardened libgrabkernel2 / libpartial (shipped in Tools/hardened): if the
      index misses, grab_images() resolves the firmware URL at runtime, walks
      every candidate, retries each three times and verifies the digest from
      BuildManifest.plist. This is the "no prebuilt index needed" property.
  L3  The upstream failure path (no multi-GB IPSW fallback).

The two .a files were built with Xcode from the sources in
Tools/hardened/src and are fat arm64 + arm64e, matching the upstream
Dependencies directory byte-for-byte in ABI. Both Dopamine-roothide 3.x and
official Dopamine 3.0.13 ship the identical upstream .a pair, so the same
replacement works for both.

Also applies the NULL-safety fixes from CHANGES.patch (boot_manifest_hash,
activePrebootPath, ensureJailbreakRootExists, SPTM/TXM preboot lookups).

Every edit is idempotent. Missing optional anchors are reported and skipped,
so an upstream drift does not silently corrupt a build.
"""

import argparse
import hashlib
import os
import re
import shutil
import sys

LIBS = ("libgrabkernel2.a", "libpartial.a")


def log(message):
    print("[hardening] " + message, flush=True)


def read_text(path):
    with open(path, "r", encoding="utf-8", newline="") as handle:
        return handle.read()


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        handle.write(text)


def adapt(text, sample):
    """Match the line endings of the file being edited (CI clones use LF,
    Windows checkouts often use CRLF). Never emit mixed line endings."""
    if "\r\n" in sample:
        return text.replace("\r\n", "\n").replace("\n", "\r\n")
    return text


def replace_libs(here, repo):
    source_dir = os.path.join(here, "hardened")
    target_dir = os.path.join(repo, "Application", "Dopamine", "Dependencies")
    if not os.path.isdir(target_dir):
        raise SystemExit("[hardening] missing Dependencies directory: " + target_dir)
    for name in LIBS:
        src = os.path.join(source_dir, name)
        dst = os.path.join(target_dir, name)
        with open(src, "rb") as handle:
            payload = handle.read()
        if payload[:4] != b"\xca\xfe\xba\xbe":
            raise SystemExit("[hardening] not a fat Mach-O archive: " + src)
        if not os.path.isfile(dst):
            raise SystemExit("[hardening] upstream dependency missing: " + dst)
        shutil.copyfile(src, dst)
        log("%s -> %s (%d bytes, sha256 %s)" %
            (name, dst, len(payload), hashlib.sha256(payload).hexdigest()[:12]))


BOOT_MANIFEST_NEW = r'''char *boot_manifest_hash(void)
{
	static char *gBuf = NULL;
	static char gEmpty[] = "";

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		io_registry_entry_t registryEntry = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen");
		if (registryEntry) {
			CFDataRef bootManifestHashData = IORegistryEntryCreateCFProperty(registryEntry, CFSTR("boot-manifest-hash"), NULL, 0);
			// The lookup can come back empty (or not be CFData) before the
			// jailbreak is running. Dereferencing it unconditionally used to
			// crash; callers now get an empty string and treat the preboot
			// path as unavailable.
			if (bootManifestHashData != NULL && CFGetTypeID(bootManifestHashData) == CFDataGetTypeID()) {
				CFIndex bootManifestHashLength = CFDataGetLength(bootManifestHashData);

				if (bootManifestHashLength > 0) {
					gBuf = malloc((bootManifestHashLength * 2 * sizeof(char)) + sizeof(char));
					unsigned char *buf = (unsigned char *)CFDataGetBytePtr(bootManifestHashData);
					convert_data_to_hex_string(buf, bootManifestHashLength, gBuf);
				}

				CFRelease(bootManifestHashData);
			}

			IOObjectRelease(registryEntry);
		}
	});

	return gBuf ? gBuf : gEmpty;
}'''

BOOT_MANIFEST_RE = re.compile(r"char \*boot_manifest_hash\(void\)\s*\n\{.*?\n\}", re.S)


def patch_util_c(repo):
    target = os.path.join(repo, "BaseBin", "libjailbreak", "src", "util.c")
    if not os.path.isfile(target):
        raise SystemExit("[hardening] missing " + target)
    src = read_text(target)
    if "static char gEmpty[]" in src:
        log("util.c boot_manifest_hash already hardened")
        return
    match = BOOT_MANIFEST_RE.search(src)
    if not match:
        raise SystemExit("[hardening] cannot locate boot_manifest_hash() in util.c")
    src = src[:match.start()] + adapt(BOOT_MANIFEST_NEW, src) + src[match.end():]
    write_text(target, src)
    log("util.c boot_manifest_hash hardened (NULL/type guard + IOObjectRelease)")


ACTIVE_PREBOOT_OLD = r'''- (NSString *)activePrebootPath
{
    NSString *bootManifestString = [NSString stringWithUTF8String:boot_manifest_hash()];
    return [[self privatePrebootPath] stringByAppendingPathComponent:bootManifestString];
}'''

ACTIVE_PREBOOT_NEW = r'''- (NSString *)activePrebootPath
{
    // boot_manifest_hash() returns an empty string when the device tree lookup
    // yields nothing. Returning nil here lets callers skip the preboot
    // candidate instead of passing NULL to stringWithUTF8String:.
    const char *hash = boot_manifest_hash();
    if (!hash || hash[0] == '\0') {
        return nil;
    }

    NSString *bootManifestString = [NSString stringWithUTF8String:hash];
    if (!bootManifestString.length) {
        return nil;
    }

    return [[self privatePrebootPath] stringByAppendingPathComponent:bootManifestString];
}'''

ENSURE_ROOT_OLD = r'''        NSString *activePrebootPath = [self activePrebootPath];

        NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'''

ENSURE_ROOT_NEW = r'''        NSString *activePrebootPath = [self activePrebootPath];
        if (!activePrebootPath.length) {
            // Without a preboot hash there is nowhere to stage the jailbreak.
            return [NSError errorWithDomain:@"DOPrebootError" code:1 userInfo:@{NSLocalizedDescriptionKey: @"The active preboot volume could not be determined."}];
        }

        NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";'''

SPTM_OLD = r'''        NSString *sptmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sptmPath]) {'''

SPTM_NEW = r'''        NSString *prebootPath = [self activePrebootPath];
        NSString *sptmPath = prebootPath ? [prebootPath stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4"] : nil;
        if (sptmPath && [[NSFileManager defaultManager] fileExistsAtPath:sptmPath]) {'''

TXM_OLD = r'''        NSString *txmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:txmPath]) {'''

TXM_NEW = r'''        NSString *prebootPath = [self activePrebootPath];
        NSString *txmPath = prebootPath ? [prebootPath stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4"] : nil;
        if (txmPath && [[NSFileManager defaultManager] fileExistsAtPath:txmPath]) {'''


def patch_env_manager(repo):
    target = os.path.join(repo, "Application", "Dopamine", "Jailbreak",
                          "DOEnvironmentManager.m")
    if not os.path.isfile(target):
        raise SystemExit("[hardening] missing " + target)
    src = read_text(target)
    original = src
    required = (("activePrebootPath", ACTIVE_PREBOOT_OLD, ACTIVE_PREBOOT_NEW,
                 "const char *hash = boot_manifest_hash();"),
                ("ensureJailbreakRootExists", ENSURE_ROOT_OLD, ENSURE_ROOT_NEW,
                 '@"DOPrebootError"'))
    optional = (("accessibleSPTMPath", SPTM_OLD, SPTM_NEW,
                 "prebootPath ? [prebootPath stringByAppendingPathComponent:@\"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4\"]"),
                ("accessibleTXMPath", TXM_OLD, TXM_NEW,
                 "prebootPath ? [prebootPath stringByAppendingPathComponent:@\"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4\"]"))

    for group in (required, optional):
        for label, old, new, marker in group:
            old = adapt(old, src)
            new = adapt(new, src)
            if marker in src:
                log("%s already hardened" % label)
            elif old not in src:
                if group is required:
                    raise SystemExit("[hardening] required anchor missing: " + label)
                log("SKIP %s (upstream drift, anchor absent)" % label)
            else:
                src = src.replace(old, new, 1)
                log("%s hardened" % label)

    if src != original:
        write_text(target, src)
        log("DOEnvironmentManager.m written (line endings preserved)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True, help="path to the Dopamine checkout")
    args = parser.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.abspath(args.repo)
    log("repo = " + repo)
    replace_libs(here, repo)
    patch_util_c(repo)
    patch_env_manager(repo)
    log("done: L1 index path untouched, L2 hardened runtime resolve installed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
