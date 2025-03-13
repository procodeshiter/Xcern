#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#define CHECK_PTR(ptr) ((ptr) != NULL && (ptr) != (void *)0x20)
#define SPOOF_VALUE ".._."

#define GETRR_OFFSET 0x51186B8

typedef struct {
    const char* argspoof;
    const char* noncespoof;
} SpoofData;

@interface Spoofer : NSObject
@property (nonatomic, assign) const char* arg;
@property (nonatomic, assign) const char* nonce;

- (instancetype)initWithArg:(const char*)arg nonce:(const char*)nonce;
- (void*)execute;
@end

@implementation Spoofer
- (instancetype)initWithArg:(const char*)arg nonce:(const char*)nonce {
    self = [super init];
    if (self) {
        _arg = arg;
        _nonce = nonce;
    }
    return self;
}

- (BOOL)isValid {
    return CHECK_PTR(_arg) && CHECK_PTR(_nonce) && (strcmp(_arg, _nonce) != 0);
}

- (void)spoofMemory:(uint64_t)address value:(const char*)value {
    memcpy((void*)address, value, strlen(value) + 1);
}

- (void*)execute {
    if ([self isValid]) {
        SpoofData data = {SPOOF_VALUE, SPOOF_VALUE};
        [self spoofMemory:(uint64_t)_arg value:data.argspoof];
        [self spoofMemory:(uint64_t)_nonce value:data.noncespoof];
        return (void*)0x1;
    }
    return NULL;
}
@end

BOOL (*original_function)(void);
BOOL replaced_function() {
    return NO;
}

void* (*orig_getrr)(const char*, const char*);
void* getrr(const char* arg, const char* nonce) {
    Spoofer* spoofer = [[Spoofer alloc] initWithArg:arg nonce:nonce];
    return [spoofer execute];
}

typedef struct {
    void* ptr_addr;
    void* hook_addr;
    void* orig_addr;
    BOOL is_swap_hook;
} HookInfo;

NSMutableArray<NSValue*>* hooked_funcs;

void* (*orig_dlsym)(void*, const char*);
void* hooked_dlsym(void* handle, const char* symbol) {
    if (strcmp(symbol, "getrr") == 0) {
        return getrr;
    }
    return orig_dlsym(handle, symbol);
}

static int (*orig_close)(int);
static int (*orig_open)(const char *, int, ...);

int my_close(int fd) {
    printf("Calling real close(%d)\n", fd);
    return orig_close(fd);
}

int my_open(const char *path, int oflag, ...) {
    va_list ap = {0};
    mode_t mode = 0;

    if ((oflag & O_CREAT) != 0) {
        va_start(ap, oflag);
        mode = va_arg(ap, int);
        va_end(ap);
        printf("Calling real open('%s', %d, %d)\n", path, oflag, mode);
        return orig_open(path, oflag, mode);
    } else {
        printf("Calling real open('%s', %d)\n", path, oflag);
        return orig_open(path, oflag, mode);
    }
}

void rebind_functions() {
    void* libHandle = dlopen(NULL, RTLD_NOW);
    orig_dlsym = dlsym(libHandle, "dlsym");

    struct rebinding rebindings[] = {
        {"dlsym", (void*)hooked_dlsym, (void**)&orig_dlsym},
        {"close", my_close, (void *)&orig_close},
        {"open", my_open, (void *)&orig_open},
        {"getrr", getrr, (void **)&orig_getrr}
    };
    rebind_symbols(rebindings, 4);
}

__attribute__((constructor)) void init() {
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"Welcome"
                                                                     message:@"Bypass by @worldt0screen"
                                                              preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *okAction = [UIAlertAction actionWithTitle:@"OK"
                                                           style:UIAlertActionStyleDefault
                                                         handler:nil];
        [alert addAction:okAction];

        UIWindow *keyWindow = nil;
        NSSet<UIScene *> *connectedScenes = [UIApplication sharedApplication].connectedScenes;
        for (UIScene *scene in connectedScenes) {
            if (scene.activationState == UISceneActivationStateForegroundActive && [scene isKindOfClass:[UIWindowScene class]]) {
                UIWindowScene *windowScene = (UIWindowScene *)scene;
                keyWindow = windowScene.windows.firstObject;
                break;
            }
        }

        if (keyWindow) {
            UIViewController *rootViewController = keyWindow.rootViewController;
            [rootViewController presentViewController:alert animated:YES completion:nil];
        } else {
            NSLog(@"Failed to get keyWindow for displaying alert.");
        }
    });

    hooked_funcs = [NSMutableArray new];

    void* getrr_delegate = (void*)(GETRR_OFFSET);

    for (int i = 0; i < 5; i++) {
        NSLog(@"Using getrr_delegate #%d: %p", i + 1, getrr_delegate);
    }

    orig_getrr = dlsym(getrr_delegate, "getrr");
    if (orig_getrr) {
        struct rebinding rebindings[] = {
            {"getrr", getrr, (void **)&orig_getrr}
        };
        rebind_symbols(rebindings, 1);
    } else {
        NSLog(@"Failed to find getrr function.");
    }

    if (original_function) {
        struct rebinding rebindings[] = {
            {"original_function", replaced_function, (void **)&original_function}
        };
        rebind_symbols(rebindings, 1);
    } else {
        NSLog(@"Failed to find original_function.");
    }

    rebind_functions();
}
