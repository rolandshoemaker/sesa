package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/crypto/ssh"
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

// getAppleError extracts a human readable error from a CFErrorRef and
// releases the reference
func getAppleError(appleErr C.CFErrorRef) string {
	defer C.CFRelease(C.CFTypeRef(appleErr))
	cfStr := C.CFErrorCopyDescription(appleErr)
	defer C.CFRelease(C.CFTypeRef(cfStr))
	// I _think_ apple handles the memory management here,
	// we shouldn't need to free cStr.
	cStr := C.CFStringGetCStringPtr(cfStr, C.kCFStringEncodingUTF8)
	if cStr == nil {
		return "failed to read apple error"
	}
	return C.GoString(cStr)
}

// cfDataToBytes extracts the contents of a CFDataRef into a []byte
func cfDataToBytes(dataRef C.CFDataRef) []byte {
	b := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(dataRef)), C.int(C.CFDataGetLength(dataRef)))
	return b
}

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
		case C.CFDataRef:
			values = append(values, unsafe.Pointer(t))
		case *C.NSObject:
			values = append(values, unsafe.Pointer(t))
		default:
			panic("unknown type")
		}
	}
	return C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &values[0], C.CFIndex(len(m)), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

func generateKey(keyLabel string) {
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

	cfLabel := C.CFStringCreateWithCString(C.kCFAllocatorDefault, C.CString(keyLabel), C.kCFStringEncodingASCII)
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
		C.kSecAttrTokenID:       C.kSecAttrTokenIDSecureEnclave,
		C.kSecAttrKeyType:       C.kSecAttrKeyTypeECSECPrimeRandom,
		C.kSecAttrKeySizeInBits: C.idx(cfBits),
		C.kSecAttrLabel:         C.idx(cfLabel),
		C.kSecAttrIsPermanent:   C.kCFBooleanTrue,
		C.kSecPrivateKeyAttrs: dictToCFDict(map[C.CFStringRef]interface{}{
			// presumably there is a more idiomatic way to do this
			// but for the life of me i can't figure it out...
			C.kSecAttrAccessControl: C.accessControl(
				C.CFTypeRef(C.kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly),
				C.kSecAccessControlPrivateKeyUsage|C.kSecAccessControlTouchIDAny,
			),
		}),
	})
	defer C.CFRelease(C.CFTypeRef(attrs))

	privRef := C.SecKeyCreateRandomKey(attrs, &appleErr)
	if privRef == 0 || appleErr != 0 {
		panic(getAppleError(appleErr))
	}
	defer C.CFRelease(C.CFTypeRef(privRef))

	pubRef := C.SecKeyCopyPublicKey(privRef)
	if pubRef == 0 {
		panic("couldn't create pub key ref")
	}
	defer C.CFRelease(C.CFTypeRef(pubRef))

	cfData := C.SecKeyCopyExternalRepresentation(pubRef, &appleErr)
	if cfData == 0 || appleErr != 0 {
		panic(getAppleError(appleErr))
	}
	ansiBytes := cfDataToBytes(cfData)
	C.CFRelease(C.CFTypeRef(cfData))

	x, y := elliptic.Unmarshal(elliptic.P256(), ansiBytes)
	if x == nil || y == nil {
		panic("failed to parse extracted public key")
	}
	sshPK, err := ssh.NewPublicKey(&ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	})
	if err != nil {
		panic(err)
	}
	fmt.Print(string(ssh.MarshalAuthorizedKey(sshPK)))
}

func listKeys() {
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
		if ret == -25300 {
			fmt.Println("no keys found")
			return
		}
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
	for i := C.CFIndex(0); i < count; i++ {
		p := C.CFArrayGetValueAtIndex(C.CFArrayRef(data), i)
		item := C.CFDictionaryRef(p)
		labelP := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecAttrLabel))
		var label string
		if labelP != nil {
			cfLabel := C.CFStringRef(labelP)
			cLabel := C.CFStringGetCStringPtr(cfLabel, C.kCFStringEncodingUTF8)
			if cLabel != nil {
				label = C.GoString(cLabel)
			} else {
				label = "<nil>"
			}
		} else {
			label = "<nil>"
		}
		fmt.Printf("label: %s\n", label)

		appLabelRef := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecAttrApplicationLabel))
		var appLabel string
		if appLabelRef != nil {
			lbl := cfDataToBytes(C.CFDataRef(appLabelRef))
			appLabel = hex.EncodeToString(lbl)
		} else {
			panic("this shouldn't be able to happen...")
		}
		fmt.Printf("key ID: %s\n", appLabel)

		privRefP := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecValueRef))
		pubRef := C.SecKeyCopyPublicKey(C.SecKeyRef(privRefP))
		if pubRef == 0 {
			fmt.Println("bad bad bad bad SecKeyCopyPublicKey")
			continue
		}
		defer C.CFRelease(C.CFTypeRef(pubRef))
		var appleErr C.CFErrorRef
		cfData := C.SecKeyCopyExternalRepresentation(C.SecKeyRef(pubRef), &appleErr)
		if cfData == 0 || appleErr != 0 {
			panic(getAppleError(appleErr))
		}
		ansiBytes := cfDataToBytes(cfData)
		C.CFRelease(C.CFTypeRef(cfData))

		x, y := elliptic.Unmarshal(elliptic.P256(), ansiBytes)
		if x == nil || y == nil {
			panic("failed to parse extracted public key")
		}
		sshPK, err := ssh.NewPublicKey(&ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		})
		if err != nil {
			panic(err)
		}
		fmt.Printf("public key: %s", string(ssh.MarshalAuthorizedKey(sshPK)))

		fmt.Println("-----")
	}
}

func deleteKey(appLabelStr string) error {
	appLabel, err := hex.DecodeString(appLabelStr)
	if err != nil {
		return err
	}
	cLbl := C.CBytes(appLabel)
	cfLbl := C.CFDataCreate(C.kCFAllocatorDefault, (*C.uchar)(cLbl), C.CFIndex(len(appLabel)))
	defer C.CFRelease(C.CFTypeRef(cfLbl))
	defer C.free(cLbl) // do i need to do both?

	query := dictToCFDict(map[C.CFStringRef]interface{}{
		C.kSecAttrTokenID:          C.kSecAttrTokenIDSecureEnclave,
		C.kSecAttrApplicationLabel: cfLbl,
		C.kSecClass:                C.kSecClassKey,
		C.kSecReturnAttributes:     C.kCFBooleanTrue,
		C.kSecMatchLimit:           C.kSecMatchLimitAll,
	})
	defer C.CFRelease(C.CFTypeRef(query))
	ret := C.SecItemDelete(query)
	if ret != C.errSecSuccess {
		if ret == -25300 {
			fmt.Println("no matching key found")
			return nil
		}
		appleErr := C.SecCopyErrorMessageString(ret, C.NULL)
		defer C.CFRelease(C.CFTypeRef(appleErr))
		cStr := C.CFStringGetCStringPtr(appleErr, C.kCFStringEncodingUTF8)
		if cStr == nil {
			fmt.Println("SecItemDelete failed: failed to read apple error")
			os.Exit(1)
		}
		fmt.Printf("SecItemCopyDelete failed: %s\n", C.GoString(cStr))
		os.Exit(1)
	}
	return nil
}

func main() {
	generateFlags := flag.NewFlagSet("generate", flag.ExitOnError)
	keyLabel := generateFlags.String("key-label", "", "Human readable key label (minimum 10 characters)")

	deleteFlags := flag.NewFlagSet("delete", flag.ExitOnError)
	keyID := deleteFlags.String("key-id", "", "key ID to delete (required)")

	if len(os.Args) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "list":
		listKeys()
	case "generate":
		generateFlags.Parse(os.Args[2:])
		if *keyLabel == "" {
			generateFlags.Usage()
			os.Exit(1)
		} else if len(*keyLabel) < 10 {
			fmt.Println("macOS requires key labels be at least 10 characters long (who knows why)")
			os.Exit(1)
		}
		generateKey(*keyLabel)
	case "delete":
		deleteFlags.Parse(os.Args[2:])
		if *keyID == "" {
			deleteFlags.Usage()
			os.Exit(1)
		}
		deleteKey(*keyID)
	default:
		flag.Usage()
		os.Exit(1)
	}
}
