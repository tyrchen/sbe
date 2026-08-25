#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdio.h>

int main(void) {
    const void *keys[] = {kSecClass, kSecAttrService, kSecReturnData};
    const void *values[] = {
        kSecClassGenericPassword,
        CFSTR("sbe-security-test"),
        kCFBooleanTrue,
    };
    CFDictionaryRef query = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    if (result != NULL) {
        CFRelease(result);
    }
    CFRelease(query);
    if (status == errSecSuccess) {
        fputs("unexpected keychain access\n", stderr);
        return 0;
    }
    return 1;
}
