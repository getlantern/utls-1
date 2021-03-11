// Copyright 2017 Google Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"reflect"
	"testing"
	"time"
)

func assertEquality(t *testing.T, fieldName string, expected, actual interface{}) {
	if kActual, ok := actual.(KeyShare); ok {
		kExpected := expected.(KeyShare)
		assertEquality(t, fieldName, kExpected.Group, kActual.Group)
		return
	}

	if fieldName == "SupportedCurves" || fieldName == "KeyShares" {
		cExpected := expected.(CurveID)
		cActual := actual.(CurveID)
		if isGREASEUint16(uint16(cExpected)) && isGREASEUint16(uint16(cActual)) {
			return
		}
	}

	if fieldName == "SupportedVersions" || fieldName == "CipherSuites" {
		cExpected := expected.(uint16)
		cActual := actual.(uint16)
		if isGREASEUint16(cExpected) && isGREASEUint16(cActual) {
			return
		}
	}

	if expected != actual {
		t.Errorf("%v fields not equal, expected: %v, got: %v", fieldName, expected, actual)
	}
}

func compareClientHelloFields(t *testing.T, fieldName string, expected, actual *ClientHelloMsg) {
	rExpected := reflect.ValueOf(expected)
	if rExpected.Kind() != reflect.Ptr || rExpected.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}
	rActual := reflect.ValueOf(actual)
	if rActual.Kind() != reflect.Ptr || rActual.Elem().Kind() != reflect.Struct {
		t.Errorf("Error using reflect to compare Hello fields")
	}

	rExpected = rExpected.Elem()
	rActual = rActual.Elem()

	fExpected := rExpected.FieldByName(fieldName)
	fActual := rActual.FieldByName(fieldName)
	if !(fExpected.IsValid() && fActual.IsValid()) {
		t.Errorf("Error using reflect to lookup Hello field name: %v", fieldName)
	}

	if fExpected.Kind() == reflect.Slice {
		sExpected := fExpected.Slice(0, fExpected.Len())
		sActual := fActual.Slice(0, fActual.Len())

		if sExpected.Len() != sActual.Len() {
			t.Errorf("%v fields slice length not equal, expected: %v, got: %v", fieldName, fExpected, fActual)
		}

		for i := 0; i < sExpected.Len(); i++ {
			assertEquality(t, fieldName, sExpected.Index(i).Interface(), sActual.Index(i).Interface())
		}
	} else {
		assertEquality(t, fieldName, fExpected.Interface(), fActual.Interface())
	}
}

func checkUTLSExtensionsEquality(t *testing.T, expected, actual TLSExtension) {
	if _, ok := expected.(*UtlsGREASEExtension); ok {
		if _, ok := actual.(*UtlsGREASEExtension); ok {
			// Good enough that they're both GREASE
			return
		}
	}

	if expected.Len() != actual.Len() {
		t.Errorf("extension types length not equal\nexpected: %#v\ngot: %#v", expected, actual)
	}

	actualBytes, err := ioutil.ReadAll(actual)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	expectedBytes, err := ioutil.ReadAll(expected)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	logInequality := func() {
		t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
	}

	if !bytes.Equal(expectedBytes, actualBytes) {
		// handle all the cases where GREASE or other factors can cause byte unalignment

		// at this point concrete types must match
		expectedType := reflect.TypeOf(expected)
		actualType := reflect.TypeOf(actual)
		if expectedType != actualType {
			t.Errorf("extensions not equal\nexpected: %#v\nbytes:%#x\ngot: %#v\nbytes: %#x", expected, expectedBytes, actual, actualBytes)
			return
		}

		switch expectedExtension := expected.(type) {
		case *SupportedCurvesExtension:
			actualExtension := expected.(*SupportedCurvesExtension)
			for i, expectedCurve := range expectedExtension.Curves {
				actualCurve := actualExtension.Curves[i]
				if expectedCurve == actualCurve {
					continue
				}
				if isGREASEUint16(uint16(expectedCurve)) && isGREASEUint16(uint16(actualCurve)) {
					continue
				}
				logInequality()
				return
			}
		case *KeyShareExtension:
			actualExtension := expected.(*KeyShareExtension)
			for i, expectedKeyShare := range expectedExtension.KeyShares {
				actualKeyShare := actualExtension.KeyShares[i]
				if bytes.Equal(actualKeyShare.Data, expectedKeyShare.Data) {
					continue
				}
				if isGREASEUint16(uint16(expectedKeyShare.Group)) && isGREASEUint16(uint16(actualKeyShare.Group)) {
					continue
				}
				logInequality()
				return
			}
		case *SupportedVersionsExtension:
			actualExtension := expected.(*SupportedVersionsExtension)
			for i, expectedVersion := range expectedExtension.Versions {
				actualVersion := actualExtension.Versions[i]
				if isGREASEUint16(expectedVersion) && isGREASEUint16(actualVersion) || actualVersion == expectedVersion {
					continue
				}
				logInequality()
				return
			}
		default:
			logInequality()
			return
		}
	}

}

func checkUTLSFingerPrintClientHello(t *testing.T, clientHelloID ClientHelloID, serverName string) {
	uconn := UClient(&net.TCPConn{}, &Config{ServerName: serverName}, clientHelloID)
	if err := uconn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	generatedUConn := UClient(&net.TCPConn{}, &Config{ServerName: "foobar"}, HelloCustom)
	generatedSpec, err := FingerprintClientHello(uconn.HandshakeState.Hello.Raw)
	if err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.ApplyPreset(generatedSpec); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}
	if err := generatedUConn.BuildHandshakeState(); err != nil {
		t.Errorf("got error: %v; expected to succeed", err)
	}

	if len(uconn.HandshakeState.Hello.Raw) != len(generatedUConn.HandshakeState.Hello.Raw) {
		t.Errorf("UConn from fingerprint has %d length, should have %d", len(generatedUConn.HandshakeState.Hello.Raw), len(uconn.HandshakeState.Hello.Raw))
	}

	// We can't effectively check the extensions on randomized client hello ids
	if !(clientHelloID == HelloRandomized || clientHelloID == HelloRandomizedALPN || clientHelloID == HelloRandomizedNoALPN) {
		for i, originalExtension := range uconn.Extensions {
			if _, ok := originalExtension.(*UtlsPaddingExtension); ok {
				// We can't really compare padding extensions in this way
				continue
			}

			generatedExtension := generatedUConn.Extensions[i]
			checkUTLSExtensionsEquality(t, originalExtension, generatedExtension)
		}
	}

	fieldsToTest := []string{
		"Vers", "CipherSuites", "CompressionMethods", "NextProtoNeg", "ServerName", "OcspStapling", "Scts", "SupportedCurves",
		"SupportedPoints", "TicketSupported", "SupportedSignatureAlgorithms", "SecureRenegotiation", "SecureRenegotiationSupported", "AlpnProtocols",
		"SupportedSignatureAlgorithmsCert", "SupportedVersions", "KeyShares", "EarlyData", "PskModes", "PskIdentities", "PskBinders",
	}

	for _, field := range fieldsToTest {
		compareClientHelloFields(t, field, uconn.HandshakeState.Hello, generatedUConn.HandshakeState.Hello)
	}
}

// Asserts that objA and objB have no common references. To illustrate, the following would fail:
//   ref := new(someType)
//   checkNoSharedReferences(t, foo{ref}, foo{ref})
// while the following would pass:
//   checkNoSharedReferences(t, foo{new(someType)}, foo{new(someType)})
//
// Only like fields are compared (e.g. the same field on two structs or the same element in two
// slices).
func checkNoSharedReferences(t *testing.T, objA, objB interface{}) {
	t.Helper()
	if objA == nil || objB == nil {
		return
	}
	checkNoSharedReferencesHelper(t, reflect.ValueOf(objA), reflect.ValueOf(objB), "topLevelValue")
}

func checkNoSharedReferencesHelper(t *testing.T, vA, vB reflect.Value, name string) {
	t.Helper()

	isNil := func(v reflect.Value) bool {
		zeroValue := reflect.Value{}
		if v == zeroValue {
			return true
		}
		switch v.Kind() {
		case reflect.Ptr, reflect.Chan, reflect.Func, reflect.Map, reflect.Slice:
			return v.IsNil()
		}
		return false
	}

	if isNil(vA) || isNil(vB) {
		return
	}

	if vA.Type() != vB.Type() {
		t.Errorf("expected two objects of the same type; got %v and %v", vA.Type(), vB.Type())
	}

	// First, if this is a reference type, check that A and B don't point to the same value.
	switch vA.Kind() {
	case reflect.UnsafePointer:
		t.Errorf("cannot check %v; unsafe pointer unimplemented", name)
		return
	case reflect.Chan, reflect.Func, reflect.Map:
		if vA.Pointer() == vB.Pointer() {
			t.Errorf("shared reference to %v", name)
		}
	case reflect.Slice:
		// Two distinct zero-size variables may have the same address in memory.
		// https://golang.org/ref/spec#Size_and_alignment_guarantees
		if vA.Len() != 0 && vA.Pointer() == vB.Pointer() {
			t.Errorf("shared reference to %v", name)
		}
	case reflect.Ptr:
		// Two distinct zero-size variables may have the same address in memory.
		// https://golang.org/ref/spec#Size_and_alignment_guarantees
		if vA.Type().Elem().Size() != 0 && vA.Pointer() == vB.Pointer() {
			t.Errorf("shared reference to %v", name)
		}
	}

	// Next check any contained elements.
	switch vA.Kind() {
	case reflect.Ptr, reflect.Interface:
		checkNoSharedReferencesHelper(t, vA.Elem(), vB.Elem(), name)
	case reflect.Struct:
		for i := 0; i < vA.NumField(); i++ {
			fieldName := vA.Type().Field(i).Name
			checkNoSharedReferencesHelper(t, vA.Field(i), vB.Field(i), name+"."+fieldName)
		}
	case reflect.Slice, reflect.Array:
		for i := 0; i < vA.Len() && i < vB.Len(); i++ {
			elementName := fmt.Sprintf("%s[%d]", name, i)
			checkNoSharedReferencesHelper(t, vA.Index(i), vB.Index(i), elementName)
		}
	case reflect.Map:
		for _, k := range vA.MapKeys() {
			elementName := fmt.Sprintf("%s[%v]", name, k)
			valA, valB := vA.MapIndex(k), vB.MapIndex(k)
			if valB.IsZero() {
				// k does not appear in vB.
				continue
			}
			checkNoSharedReferencesHelper(t, valA, valB, elementName)
		}
	}
}

func TestUTLSFingerprintClientHello(t *testing.T) {
	clientHellosToTest := []ClientHelloID{
		HelloChrome_58, HelloChrome_70, HelloChrome_83, HelloFirefox_55, HelloFirefox_63,
		HelloEdge_85, HelloExplorer_11, Hello360_7_5, HelloQQ_10_6, HelloIOS_11_1, HelloIOS_12_1,
		HelloRandomized, HelloRandomizedALPN, HelloRandomizedNoALPN,
	}

	serverName := "foobar"
	for _, clientHello := range clientHellosToTest {
		t.Logf("checking fingerprint generated client hello spec against %v and server name: %v", clientHello, serverName)
		checkUTLSFingerPrintClientHello(t, clientHello, serverName)
	}
}

func TestUTLSIsGrease(t *testing.T) {
	var testMap = []struct {
		version  uint16
		isGREASE bool
	}{
		{0x0a0a, true},
		{0x1a1a, true},
		{0x2a1a, false},
		{0x2a2a, true},
		{0x1234, false},
		{0x1a2a, false},
		{0xdeed, false},
		{0xb1b1, false},
		{0x0b0b, false},
	}

	for _, testCase := range testMap {
		if isGREASEUint16(testCase.version) != testCase.isGREASE {
			t.Errorf("misidentified GREASE: testing %x, isGREASE: %v", testCase.version, isGREASEUint16(testCase.version))
		}
	}
}

func TestTLSExtensionClone(t *testing.T) {
	for _, ext := range []TLSExtension{
		&NPNExtension{[]string{"a", "b", "c"}},
		&SNIExtension{"foo"},
		&StatusRequestExtension{},
		&SupportedCurvesExtension{[]CurveID{0xa, 0xb, 0xc}},
		&SupportedPointsExtension{[]uint8{0xa, 0xb, 0xc}},
		&SignatureAlgorithmsExtension{[]SignatureScheme{0xa, 0xb, 0xc}},
		&RenegotiationInfoExtension{3},
		&ALPNExtension{[]string{"a", "b", "c"}},
		&SCTExtension{},
		&SessionTicketExtension{&ClientSessionState{
			[]uint8{0x1, 0x2, 0x3},
			0xaa,
			0xbb,
			[]byte("foo"),
			[]*x509.Certificate{
				{
					Raw:                []byte("foo"),
					Signature:          []byte("bar"),
					PublicKeyAlgorithm: x509.RSA,
					Version:            100,
					SerialNumber:       big.NewInt(123456789),
				},
				{
					Raw:                []byte("bar"),
					Signature:          []byte("baz"),
					PublicKeyAlgorithm: x509.ECDSA,
					Version:            101,
					SerialNumber:       big.NewInt(987654321),
				},
			},
			[][]*x509.Certificate{
				{
					{
						Raw:                []byte("foo"),
						Signature:          []byte("bar"),
						PublicKeyAlgorithm: x509.RSA,
						Version:            100,
						SerialNumber:       big.NewInt(123456789),
					},
					{
						Raw:                []byte("bar"),
						Signature:          []byte("baz"),
						PublicKeyAlgorithm: x509.ECDSA,
						Version:            101,
						SerialNumber:       big.NewInt(987654321),
					},
				},
				{
					{
						Raw:                []byte("baz"),
						Signature:          []byte("foo"),
						PublicKeyAlgorithm: x509.DSA,
						Version:            102,
						SerialNumber:       big.NewInt(11223344),
					},
					{
						Raw:                []byte("baz"),
						Signature:          []byte("bar"),
						PublicKeyAlgorithm: x509.RSA,
						Version:            103,
						SerialNumber:       big.NewInt(55667788),
					},
				},
			},
			time.Now(),
			[]byte("bar"),
			time.Now().Add(time.Hour),
			33,
		}},
		&GenericExtension{99, []byte("foo")},
		&UtlsExtendedMasterSecretExtension{},
		&UtlsGREASEExtension{33, []byte("bar")},
		&UtlsPaddingExtension{3, true, func(_ int) (int, bool) { return 3, false }},
		&KeyShareExtension{[]KeyShare{
			{1, []byte("a")},
			{2, []byte("b")},
			{3, []byte("c")},
		}},
		&PSKKeyExchangeModesExtension{[]uint8{0xa, 0xb, 0xc}},
		&SupportedVersionsExtension{[]uint16{0x1, 0x2, 0x3}},
		&CookieExtension{[]byte("om nom nom")},
		&FakeChannelIDExtension{true},
		&FakeCertCompressionAlgsExtension{[]CertCompressionAlgo{0x1, 0x2, 0x3}},
		&FakeRecordSizeLimitExtension{0xabc},
		&FakeTokenBindingExtension{0xaa, 0xbb, []uint8{0x1, 0x2, 0x3}},
	} {
		t.Logf("testing %T", ext)
		checkUTLSExtensionsEquality(t, ext, ext.Clone())
		// We nil some of the fields when checking shared references as there are a few fields we
		// are okay sharing.
		switch e := ext.(type) {
		case *SessionTicketExtension:
			e.Session.serverCertificates = []*x509.Certificate{}
			e.Session.verifiedChains = [][]*x509.Certificate{}
			// These produce false postives as the Location will be a shared reference.
			e.Session.receivedAt, e.Session.useBy = time.Time{}, time.Time{}
		case *UtlsPaddingExtension:
			e.GetPaddingLen = nil
		}
		checkNoSharedReferences(t, ext, ext.Clone())
	}
}
