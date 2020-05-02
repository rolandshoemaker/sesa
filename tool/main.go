package main

import (
	"unsafe"
)

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework Foundation

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
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
	if accessRef == 0 {
		C.CFShow(C.CFTypeRef(appleErr))
		panic("broken")
	}
	defer C.CFRelease(C.CFTypeRef(accessRef))

	cfLabel := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString("sesa-testing-1"), C.kCFStringEncodingUTF8)
	if cfLabel == 0 {
		panic("couldnt create label :<")
	}
	defer C.CFRelease(C.CFTypeRef(cfLabel))

	short := C.short(256)
	cfBits := C.CFNumberCreate(C.kCFAllocatorDefault, C.kCFNumberShortType, unsafe.Pointer(&short))
	if cfBits == 0 {
		panic("couldn't create bits")
	}

	attrs := dictToCFDict(map[C.CFStringRef]interface{}{
		C.kSecAttrTokenID:      C.kSecAttrTokenIDSecureEnclave,
		C.kSecAttrKeyType: C.kSecAttrKeyTypeECSECPrimeRandom,
		C.kSecAttrKeySizeInBits: cfBits, // CFNumberRef
		C.kSecAttrLabel: cfLabel,
		C.kSecAttrIsPermanent: C.kCFBooleanTrue,
	})
	defer C.CFRelease(C.CFTypeRef(attrs))

	privRef := C.SecKeyCreateRandomKey(attrs, &appleErr)
	if privRef == 0 {
		C.CFShow(C.CFTypeRef(appleErr))
		panic("couldn't create key")
	}
	defer C.CFRelease(C.CFTypeRef(privRef))

	pubRef := C.SecKeyCopyPublicKey(privRef)
	if pubRef == 0 {
		panic("couldn't create pub key ref")
	}
	defer C.CFRelease(C.CFTypeRef(pubRef))
}
