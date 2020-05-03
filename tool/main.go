package main

import (
	"fmt"
	"os"
	"unsafe"
)

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework Security -framework Foundation

#include <Foundation/Foundation.h>
#include <Security/Security.h>

typedef void* idx;

NSObject* accessControl(CFTypeRef protection, SecAccessControlCreateFlags flags) {
	CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                    protection,
                                    flags,
                                    &error);   // Ignore error
    if (error != nil) {
       	CFRelease(error);
        return NULL;
	}
	
	return (__bridge id)access;
}

*/
import "C"

func dictToCFDict(m map[C.CFStringRef]interface{}) C.CFDictionaryRef {
	var keys, values []unsafe.Pointer
	for k, v := range m {
		keys = append(keys, unsafe.Pointer(k))
		switch t := v.(type) {
		case C.CFBooleanRef:
			values = append(values, unsafe.Pointer(t))
		case C.CFStringRef:
			values = append(values, unsafe.Pointer(t))
		case C.CFDictionaryRef:
			values = append(values, unsafe.Pointer(t))
		case C.SecAccessControlRef:
			values = append(values, unsafe.Pointer(t))
		case C.idx:
			values = append(values, unsafe.Pointer(t))
		case *C.NSObject:
			values = append(values, unsafe.Pointer(t))
		default:
			panic("unknown type")
		}
	}
	return C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &values[0], C.CFIndex(len(m)), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

func main() {
	var appleErr C.CFErrorRef
	accessRef := C.SecAccessControlCreateWithFlags(
		C.kCFAllocatorDefault,
		C.CFTypeRef(C.kSecAttrAccessibleAfterFirstUnlock),
		C.kSecAccessControlPrivateKeyUsage,
		&appleErr,
	)
	if accessRef == 0 || appleErr != 0 {
		C.CFShow(C.CFTypeRef(appleErr))
		panic("couldn't create access control")
	}
	defer C.CFRelease(C.CFTypeRef(accessRef))


	cfLabel := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString("sesa-testing-3"), C.kCFStringEncodingASCII)
	if cfLabel == 0 {
		panic("couldn't create label")
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	short := C.short(256)
	cfBits := C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberShortType, unsafe.Pointer(&short))
	if cfBits == 0 {
		panic("couldn't create bits")
	}

	attrs := dictToCFDict(map[C.CFStringRef]interface{}{
		C.kSecAttrTokenID:      C.kSecAttrTokenIDSecureEnclave,
		C.kSecAttrKeyType:       C.kSecAttrKeyTypeECSECPrimeRandom,
		C.kSecAttrKeySizeInBits: C.idx(cfBits),
		C.kSecAttrLabel:         C.idx(cfLabel),
		C.kSecAttrIsPermanent:   C.kCFBooleanTrue,
		C.kSecPrivateKeyAttrs: dictToCFDict(map[C.CFStringRef]interface{}{
			// presumably there is a more idiomatic way to do this
			// but for the life of me i can't figure it out...
			C.kSecAttrAccessControl: C.accessControl(
				C.CFTypeRef(C.kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
				C.kSecAccessControlPrivateKeyUsage & C.kSecAccessControlBiometryAny,
			),
		}),
	})
	defer C.CFRelease(C.CFTypeRef(attrs))

	privRef := C.SecKeyCreateRandomKey(attrs, &appleErr)
	if privRef == 0 || appleErr != 0 {
		C.CFShow(C.CFTypeRef(appleErr))
		panic("couldn't create key")
	}
	defer C.CFRelease(C.CFTypeRef(privRef))

	pubRef := C.SecKeyCopyPublicKey(privRef)
	if pubRef == 0 {
		panic("couldn't create pub key ref")
	}
	defer C.CFRelease(C.CFTypeRef(pubRef))

	var data C.CFTypeRef
	query := dictToCFDict(map[C.CFStringRef]interface{}{
		C.kSecAttrTokenID:      C.kSecAttrTokenIDSecureEnclave,
		C.kSecClass:            C.kSecClassKey,
		C.kSecAttrKeyClass:     C.kSecAttrKeyClassPrivate,
		C.kSecAttrKeyType:      C.kSecAttrKeyTypeECSECPrimeRandom,
		C.kSecReturnRef:        C.kCFBooleanTrue,
		C.kSecReturnAttributes: C.kCFBooleanTrue,
		C.kSecMatchLimit:       C.kSecMatchLimitAll,
	})
	defer C.CFRelease(C.CFTypeRef(query))
	ret := C.SecItemCopyMatching(query, &data)
	if ret != C.errSecSuccess {
		appleErr := C.SecCopyErrorMessageString(ret, C.NULL)
		defer C.CFRelease(C.CFTypeRef(appleErr))
		cStr := C.CFStringGetCStringPtr(appleErr, C.kCFStringEncodingUTF8)
		if cStr == nil {
			fmt.Println("SecItemCopyMatching failed: failed to read apple error")
			os.Exit(1)
		}
		fmt.Printf("SecItemCopyMatching failed: %s\n", C.GoString(cStr))
		os.Exit(1)
	}
	defer C.CFRelease(data)

	count := C.CFArrayGetCount(C.CFArrayRef(data))
	fmt.Println(count)
	for i := C.CFIndex(0); i < count; i++ {
		p := C.CFArrayGetValueAtIndex(C.CFArrayRef(data), i)
		item := C.CFDictionaryRef(p)
		labelP := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecAttrLabel))
		if labelP != nil {
			cfLabel := C.CFStringRef(labelP)
			cLabel := C.CFStringGetCStringPtr(cfLabel, C.kCFStringEncodingUTF8)
			if cLabel != nil {
				fmt.Println(C.GoString(cLabel))
			} else {
				fmt.Println("no c string?")
				C.CFShow(C.CFTypeRef(cfLabel))
			}
		} else {
			fmt.Println("no label???")
		}
	}
}
