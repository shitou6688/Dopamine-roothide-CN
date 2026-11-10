#import "utils.h"
#import <Foundation/Foundation.h>
#import <stdarg.h>
#import <sys/sysctl.h>
#if !(TARGET_OS_MACCATALYST || TARGET_OS_OSX)
#import <UIKit/UIKit.h>
#endif

// Relaxin routes diagnostics through its own engine logger. Dopamine has no
// such facility, so messages go straight to stderr via NSLog, which surfaces in
// the app's console and in Dopamine's own log stream.
enum {
    RLX_ENGINE_LOG_INFO = 0,
    RLX_ENGINE_LOG_WARNING = 1,
    RLX_ENGINE_LOG_ERROR = 2,
};

static void rlx_engine_log(int32_t level, const char *subsystem, const char *message) {
    static const char *const tags[] = {"INFO", "WARN", "ERROR"};
    const char *tag = (level >= 0 && level <= 2) ? tags[level] : "INFO";
    NSLog(@"[%s] %s: %s", tag, subsystem ?: "libgrabkernel2", message ?: "");
}

static void emitLog(int32_t level, const char *format, va_list arguments) {
    NSString *formatString = [NSString stringWithUTF8String:format];
    if (!formatString) {
        return;
    }

    NSString *message = [[NSString alloc] initWithFormat:formatString arguments:arguments];
    rlx_engine_log(level, "libgrabkernel2", message.UTF8String);
}

void libgrabkernel2_log(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    emitLog(RLX_ENGINE_LOG_INFO, format, arguments);
    va_end(arguments);
}

void libgrabkernel2_warning(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    emitLog(RLX_ENGINE_LOG_WARNING, format, arguments);
    va_end(arguments);
}

void libgrabkernel2_error(const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    emitLog(RLX_ENGINE_LOG_ERROR, format, arguments);
    va_end(arguments);
}

NSString *fetchSysctlString(const char *name) {
    char buffer[256];
    size_t size = sizeof(buffer);
    if (sysctlbyname(name, buffer, &size, NULL, 0) != 0) {
        return nil;
    }
    return [NSString stringWithCString:buffer encoding:NSUTF8StringEncoding];
}

NSString *getOsStr(void) {
#if TARGET_OS_MACCATALYST || TARGET_OS_OSX
    return @"macOS";
#else
    if (NSProcessInfo.processInfo.iOSAppOnMac) {
        return @"macOS";
    } else {
        switch (UIDevice.currentDevice.userInterfaceIdiom) {
            case UIUserInterfaceIdiomPad:
                if (@available(iOS 13.0, *)) {
                    return @"iPadOS";
                }
            case UIUserInterfaceIdiomPhone:
                return @"iOS";
            case UIUserInterfaceIdiomTV:
                return @"tvOS";
            case UIUserInterfaceIdiomMac:
                return @"macOS";
            default:
                ERRLOG("Unrecognized device type %d!\n", (int)UIDevice.currentDevice.userInterfaceIdiom);
                return nil;
        }
    }
#endif

    ERRLOG("Unsupported platform!\n");
    return nil;
}

NSString* getBuild(void) {
    NSString* build = fetchSysctlString("kern.osversion");
    if (!build) {
        ERRLOG("Failed to get build!\n");
        return nil;
    }

    return build;
}

NSString* getModelIdentifier(void) {
    NSString* modelIdentifier = fetchSysctlString("hw.product");
    if (!modelIdentifier) {
        ERRLOG("Failed to get model identifier!\n");
        return nil;
    }

    return modelIdentifier;
}

NSString *getBoardconfig(void) {
    NSString *boardconfig = fetchSysctlString("hw.target");
    if (!boardconfig) {
        ERRLOG("Failed to get boardconfig!\n");
        return nil;
    }

    return boardconfig;
}
