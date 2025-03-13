#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h" // Добавьте fishhook

#define CHECK_PTR(ptr) ((ptr) != NULL && (ptr) != (void *)0x20)
#define SPOOF_VALUE ".._."

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

void rebind_functions() {
    void* libHandle = dlopen(NULL, RTLD_NOW);
    orig_dlsym = dlsym(libHandle, "dlsym");
    struct rebinding rebindings[] = {
        {"dlsym", (void*)hooked_dlsym, (void**)&orig_dlsym}
    };
    rebind_symbols(rebindings, 1); // Используем правильную сигнатуру
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
            NSLog(@"Не удалось получить keyWindow для отображения alert.");
        }
    });

    hooked_funcs = [NSMutableArray new];
    rebind_functions(); // Вызываем исправленную функцию
}