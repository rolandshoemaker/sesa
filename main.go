package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -framework CoreFoundation -framework Security -framework Foundation

#include <Foundation/Foundation.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
*/
import "C"

var errUnimplemented = errors.New("functionality unimplemented")

type seAgent struct {
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
		}
	}
	return C.CFDictionaryCreate(C.kCFAllocatorDefault, &keys[0], &values[0], C.CFIndex(len(m)), &C.kCFTypeDictionaryKeyCallBacks, &C.kCFTypeDictionaryValueCallBacks)
}

// seKey satisfies crypto.Signer
type seKey struct {
	agent.Key
	pk  crypto.PublicKey
	ref C.SecKeyRef
}

func (sk *seKey) Public() crypto.PublicKey {
	return sk.pk
}

func getAppleError(appleErr C.CFErrorRef) string {
	cfStr := C.CFErrorCopyDescription(appleErr)
	defer C.CFRelease(C.CFTypeRef(cfStr))
	cStr := C.CFStringGetCStringPtr(cfStr, C.kCFStringEncodingUTF8)
	if cStr == nil {
		return "failed to read apple error"
	}
	C.CFRelease(C.CFTypeRef(appleErr))
	return C.GoString(cStr)
}

func (sk *seKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	var appleErr C.CFErrorRef
	cDigest := C.CBytes(digest)
	cfDigest := C.CFDataCreate(C.kCFAllocatorDefault, (*C.uchar)(cDigest), C.CFIndex(len(digest)))
	defer C.CFRelease(C.CFTypeRef(cfDigest))
	defer C.free(cDigest) // do i need to do both?
	cfSig := C.SecKeyCreateSignature(sk.ref, C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256, cfDigest, &appleErr)
	if cfSig == 0 {
		fmt.Println("bad bad bad", appleErr)
		return nil, fmt.Errorf("SecKeyCreateSignature failed: %s", getAppleError(appleErr))
	}
	sig := C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(cfSig)), C.int(C.CFDataGetLength(cfSig)))
	C.CFRelease(C.CFTypeRef(cfSig))
	return sig, nil
}

// parseANSIPub parses a ANSI X9.63 format public key
func parseANSIPub(b []byte) (*ecdsa.PublicKey, error) {
	if len(b) != 65 {
		return nil, errors.New("unexpected key length")
	}
	xBytes, yBytes := b[1:33], b[33:]
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     big.NewInt(0).SetBytes(xBytes),
		Y:     big.NewInt(0).SetBytes(yBytes),
	}, nil
}

func getKeys() ([]seKey, error) {
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
			return nil, errors.New("SecItemCopyMatching failed: failed to read apple error")
		}
		return nil, fmt.Errorf("SecItemCopyMatching failed: %s", C.GoString(cStr))
	}
	defer C.CFRelease(data)

	count := C.CFArrayGetCount(C.CFArrayRef(data))

	var keys []seKey

	for i := C.CFIndex(0); i < count; i++ {
		var k seKey
		p := C.CFArrayGetValueAtIndex(C.CFArrayRef(data), i)
		item := C.CFDictionaryRef(p)
		labelP := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecAttrLabel))
		if labelP != nil {
			cfLabel := C.CFStringRef(labelP)
			cLabel := C.CFStringGetCStringPtr(cfLabel, C.kCFStringEncodingUTF8)
			if cLabel != nil {
				k.Comment = fmt.Sprintf("SE key: %s", C.GoString(cLabel))
			}
		}

		privRefP := C.CFDictionaryGetValue(item, unsafe.Pointer(C.kSecValueRef))
		k.ref = C.SecKeyRef(privRefP)
		pubRefP := C.SecKeyCopyPublicKey(C.SecKeyRef(privRefP))
		if pubRefP == 0 {
			fmt.Println("bad bad bad bad SecKeyCopyPublicKey")
			continue
		}
		var appleErr C.CFErrorRef
		cfData := C.SecKeyCopyExternalRepresentation(pubRefP, &appleErr)
		if cfData == 0 {
			// typically this is going to be because we aren't authorized to extract the public
			// key, just ignore and move on (we could log, but it's not going to be very
			// useful)
			C.CFRelease(C.CFTypeRef(appleErr))
			continue
		}
		derStart := C.CFDataGetBytePtr(cfData)
		der := C.GoBytes(unsafe.Pointer(derStart), C.int(C.CFDataGetLength(cfData)))
		C.CFRelease(C.CFTypeRef(cfData))

		gk, err := parseANSIPub(der)
		if err != nil {
			fmt.Println(err)
			continue
		}
		k.pk = gk
		sshPK, err := ssh.NewPublicKey(gk)
		if err != nil {
			fmt.Println(err)
			continue
		}
		k.Format = sshPK.Type()
		k.Blob = sshPK.Marshal()
		C.CFRetain(C.CFTypeRef(k.ref)) // hold onto the SecKeyRef until we know we don't need it
		keys = append(keys, k)
	}
	return keys, nil
}

// List returns the identities known to the agent.
func (a *seAgent) List() ([]*agent.Key, error) {

	seKeys, err := getKeys()
	if err != nil {
		return nil, err
	}

	sshKeys := make([]*agent.Key, len(seKeys))
	for i := range seKeys {
		C.CFRelease(C.CFTypeRef(seKeys[i].ref))
		sshKeys[i] = &seKeys[i].Key
	}

	return sshKeys, nil
}

// Sign has the agent sign the data using a protocol 2 key as defined
// in [PROTOCOL.agent] section 2.6.2.
func (a *seAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	keys, err := getKeys()
	if err != nil {
		return nil, err
	}
	pkBytes := key.Marshal()
	for _, k := range keys {
		if bytes.Equal(k.Blob, pkBytes) {
			signer, err := ssh.NewSignerFromSigner(&k)
			if err != nil {
				return nil, err
			}
			return signer.Sign(nil, data)
		}
	}

	return nil, errors.New("unknown key")
}

// Signers returns signers for all the known keys.
func (a *seAgent) Signers() ([]ssh.Signer, error) {
	keys, err := getKeys()
	if err != nil {
		return nil, err
	}
	signers := make([]ssh.Signer, len(keys))
	for i, k := range keys {
		signer, err := ssh.NewSignerFromSigner(&k) // is this pointer loop brokenness?
		if err != nil {
			return nil, err
		}
		signers[i] = signer
	}
	return signers, nil
}

// Add adds a private key to the agent. It is not implemented.
func (a *seAgent) Add(key agent.AddedKey) error {
	return errUnimplemented
}

// Remove removes all identities with the given public key. It is not implemented.
func (a *seAgent) Remove(key ssh.PublicKey) error {
	return errUnimplemented
}

// RemoveAll removes all identities. It is not implemented.
func (a *seAgent) RemoveAll() error {
	return errUnimplemented
}

// Lock locks the agent. Sign and Remove will fail, and List will empty an empty list. It is not implemented.
func (a *seAgent) Lock(passphrase []byte) error {
	return errUnimplemented
}

// Unlock undoes the effect of Lock. It is not implemented.
func (a *seAgent) Unlock(passphrase []byte) error {
	return errUnimplemented
}

func main() {
	var defaultPath string
	if userCacheDir, err := os.UserCacheDir(); err == nil {
		defaultPath = filepath.Join(userCacheDir, "sesa")
		if err := os.MkdirAll(defaultPath, os.ModePerm); err != nil {
			log.Fatalf("failed to create socket cache directory: %s\n", err)
		}
	}
	defaultPath = filepath.Join(defaultPath, "agent.sock")
	sockPath := flag.String("sock", defaultPath, "")
	flag.Parse()

	os.Remove(*sockPath)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: *sockPath, Net: "unix"})
	if err != nil {
		log.Fatalf("failed to listen on %q: %s\n", *sockPath, err)
	}
	log.Printf("Listening on %q\n", *sockPath)

	a := &seAgent{}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("failed to accept connection: %s\n", err)
		}
		if err := agent.ServeAgent(a, conn); err != nil && err != io.EOF {
			log.Printf("failed to serve request: %s\n", err)
		}
	}
}
