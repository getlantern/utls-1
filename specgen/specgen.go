// Package specgen provides a utility for generating utls.ClientHelloSpec.
package specgen

import (
	"errors"
	"fmt"
	"io"
	"reflect"

	tls "github.com/getlantern/utls"
)

const (
	// When we print byte slices, we print this many bytes per line.
	bytesPerLine = 12

	tlsRecordHeaderLen = 5
)

// WriteHelloSpec writes a utls.ClientHelloSpec corresponding to the input ClientHello.
//
// packagePrefix can be used to control the package qualifier on utls definitions. For example, if
// packagePrefix is provided as "tls", then cipher suites will be specified like
// "tls.TLS_AES_128_GCM_SHA256" in the output code. If packagePrefix is the empty string, then no
// qualifier will be used. The example cipher suite would be printed as "TLS_AES_128_GCM_SHA256".
func WriteHelloSpec(w io.Writer, clientHello []byte, packagePrefix string) error {
	prefix := ""
	if packagePrefix != "" {
		prefix = packagePrefix + "."
	}

	helloSpec, err := tls.FingerprintClientHello(clientHello[tlsRecordHeaderLen:])
	if err != nil {
		return fmt.Errorf("failed to fingerprint hello: %w", err)
	}

	fmt.Fprintf(w, "%sClientHelloSpec{\n", prefix)

	minVersionStr, ok := versions[helloSpec.TLSVersMin]
	if !ok {
		return fmt.Errorf("unrecognized min version: %#x", helloSpec.TLSVersMin)
	}
	maxVersionStr, ok := versions[helloSpec.TLSVersMax]
	if !ok {
		return fmt.Errorf("unrecognized max version: %#x", helloSpec.TLSVersMax)
	}
	fmt.Fprintf(w, "\tTLSVersMin: %s%s,\n", prefix, minVersionStr)
	fmt.Fprintf(w, "\tTLSVersMax: %s%s,\n", prefix, maxVersionStr)

	fmt.Fprintf(w, "\tCipherSuites: []uint16{\n")
	for _, suite := range helloSpec.CipherSuites {
		suiteStr, ok := cipherSuites[suite]
		if !ok {
			suiteStr = fmt.Sprintf("%#x", suite)
		} else {
			suiteStr = fmt.Sprintf("%s%s", prefix, suiteStr)
		}
		fmt.Fprintf(w, "\t\t%s,\n", suiteStr)
	}
	fmt.Fprintf(w, "\t},\n")

	fmt.Fprintf(w, "\tCompressionMethods: []uint8{\n")
	for _, method := range helloSpec.CompressionMethods {
		fmt.Fprintf(w, "\t\t%#x,", method)
		if method == 0 {
			fmt.Fprintf(w, " // no compression")
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "\t},\n")

	fmt.Fprintf(w, "\tExtensions: []%sTLSExtension{\n", prefix)
	for _, ext := range helloSpec.Extensions {
		if err := writeExtension(w, ext, 2, prefix); err != nil {
			return err
		}
	}
	fmt.Fprintf(w, "\t},\n")

	fmt.Fprintf(w, "}\n")

	return nil
}

func writeExtension(w io.Writer, e tls.TLSExtension, tabs int, prefix string) error {
	tabStr := ""
	for i := 0; i < tabs; i++ {
		tabStr += "\t"
	}

	switch ext := e.(type) {
	case *tls.ALPNExtension:
		fmt.Fprintf(w, "%s&%sALPNExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tAlpnProtocols: []string{\n", tabStr)

		for _, p := range ext.AlpnProtocols {
			fmt.Fprintf(w, "%s\t\t\"%s\",\n", tabStr, p)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.CookieExtension:
		// The cookie extension should not appear in the initial ClientHello:
		// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.2
		return errors.New("unexpected cookie extension")

	case *tls.FakeALPSExtension:
		fmt.Fprintf(w, "%s&%sFakeALPSExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tSupportedProtocols: []string{\n", tabStr)

		for _, p := range ext.SupportedProtocols {
			fmt.Fprintf(w, "%s\t\t\"%s\",\n", tabStr, p)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.FakeChannelIDExtension:
		fmt.Fprintf(w, "%s&%sFakeChannelIDExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tOldExtensionID: %t,\n", tabStr, ext.OldExtensionID)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.FakeRecordSizeLimitExtension:
		fmt.Fprintf(w, "%s&%sFakeRecordSizeLimitExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tLimit: %#x,\n", tabStr, ext.Limit)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.FakeTokenBindingExtension:
		fmt.Fprintf(w, "%s&%sFakeTokenBindingExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tMajorVersion: %d,\n", tabStr, ext.MinorVersion)
		fmt.Fprintf(w, "%s\tMinorVersion: %d,\n", tabStr, ext.MajorVersion)
		fmt.Fprintf(w, "%s\tKeyParameters: []uint8{\n", tabStr)

		for _, kp := range ext.KeyParameters {
			fmt.Fprintf(w, "%s\t\t%d,\n", tabStr, kp)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.FakeDelegatedCredentialsExtension:
		fmt.Fprintf(w, "%s&%sFakeDelegatedCredentialsExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tSupportedSignatureAlgorithms: []%sSignatureScheme{\n", tabStr, prefix)

		for _, alg := range ext.SupportedSignatureAlgorithms {
			algStr, ok := signatureAlgorithms[alg]
			if ok {
				algStr = fmt.Sprintf("%s%s", prefix, algStr)
			} else {
				algStr = fmt.Sprintf("%d", alg)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, algStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.GenericExtension:
		fmt.Fprintf(w, "%s&%sGenericExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tId: %d,\n", tabStr, ext.Id)
		fmt.Fprintf(w, "%s\tData: []byte{\n", tabStr)

		printByteSlice(w, ext.Data, tabs+2)

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.KeyShareExtension:
		fmt.Fprintf(w, "%s&%sKeyShareExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tKeyShares: []%sKeyShare{\n", tabStr, prefix)

		for _, ks := range ext.KeyShares {
			groupStr, ok := curves[ks.Group]
			if ok {
				groupStr = fmt.Sprintf("%s%s", prefix, groupStr)
			} else {
				groupStr = fmt.Sprintf("%d", ks.Group)
			}

			fmt.Fprintf(w, "%s\t\t{\n", tabStr)
			fmt.Fprintf(w, "%s\t\t\tGroup: %s,\n", tabStr, groupStr)

			if ks.Data != nil {
				fmt.Fprintf(w, "%s\t\t\tData: []byte{\n", tabStr)
				printByteSlice(w, ks.Data, tabs+4)
				fmt.Fprintf(w, "%s\t\t\t},\n", tabStr)
			}

			fmt.Fprintf(w, "%s\t\t},\n", tabStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.NPNExtension:
		fmt.Fprintf(w, "%s&%sNPNExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tNextProtos: []string{\n", tabStr)

		for _, proto := range ext.NextProtos {
			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, proto)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.PSKKeyExchangeModesExtension:
		fmt.Fprintf(w, "%s&%sPSKKeyExchangeModesExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tModes: []uint8{\n", tabStr)

		for _, mode := range ext.Modes {
			modeStr, ok := pskModes[mode]
			if ok {
				modeStr = fmt.Sprintf("%s%s", prefix, modeStr)
			} else {
				modeStr = fmt.Sprintf("%#x", mode)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, modeStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.RenegotiationInfoExtension:
		fmt.Fprintf(w, "%s&%sRenegotiationInfoExtension{\n", tabStr, prefix)

		renStr, ok := renogotiations[ext.Renegotiation]
		if ok {
			renStr = fmt.Sprintf("%s%s", prefix, renStr)
		} else {
			renStr = fmt.Sprintf("%d", ext.Renegotiation)
		}

		fmt.Fprintf(w, "%s\tRenegotiation: %s,\n", tabStr, renStr)

		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.SCTExtension:
		fmt.Fprintf(w, "%s&%sSCTExtension{},\n", tabStr, prefix)

	case *tls.SNIExtension:
		fmt.Fprintf(w, "%s&%sSNIExtension{},\n", tabStr, prefix)

	case *tls.SessionTicketExtension:
		fmt.Fprintf(w, "%s&%sSessionTicketExtension{},\n", tabStr, prefix)

	case *tls.SignatureAlgorithmsExtension:
		fmt.Fprintf(w, "%s&%sSignatureAlgorithmsExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tSupportedSignatureAlgorithms: []%sSignatureScheme{\n", tabStr, prefix)

		for _, alg := range ext.SupportedSignatureAlgorithms {
			algStr, ok := signatureAlgorithms[alg]
			if ok {
				algStr = fmt.Sprintf("%s%s", prefix, algStr)
			} else {
				algStr = fmt.Sprintf("%d", alg)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, algStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.StatusRequestExtension:
		fmt.Fprintf(w, "%s&%sStatusRequestExtension{},\n", tabStr, prefix)

	case *tls.SupportedCurvesExtension:
		fmt.Fprintf(w, "%s&%sSupportedCurvesExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tCurves: []%sCurveID{\n", tabStr, prefix)

		for _, curve := range ext.Curves {
			curveStr, ok := curves[curve]
			if ok {
				curveStr = fmt.Sprintf("%s%s", prefix, curveStr)
			} else {
				curveStr = fmt.Sprintf("%d", curve)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, curveStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.SupportedPointsExtension:
		fmt.Fprintf(w, "%s&%sSupportedPointsExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tSupportedPoints: []uint8{\n", tabStr)

		for _, point := range ext.SupportedPoints {
			fmt.Fprintf(w, "%s\t\t%#x,", tabStr, point)

			if point == 0 {
				fmt.Fprintf(w, " // uncompressed")
			}
			fmt.Fprintln(w)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.SupportedVersionsExtension:
		fmt.Fprintf(w, "%s&%sSupportedVersionsExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tVersions: []uint16{\n", tabStr)

		for _, version := range ext.Versions {
			versionStr, ok := versions[version]
			if ok {
				versionStr = fmt.Sprintf("%s%s", prefix, versionStr)
			} else {
				versionStr = fmt.Sprintf("%#x", version)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, versionStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.UtlsCompressCertExtension:
		fmt.Fprintf(w, "%s&%sUtlsCompressCertExtension{\n", tabStr, prefix)
		fmt.Fprintf(w, "%s\tAlgorithms: []%sCertCompressionAlgo{\n", tabStr, prefix)

		for _, alg := range ext.Algorithms {
			algStr, ok := certCompressionAlgs[alg]
			if ok {
				algStr = fmt.Sprintf("%s%s", prefix, algStr)
			} else {
				algStr = fmt.Sprintf("%d", alg)
			}

			fmt.Fprintf(w, "%s\t\t%s,\n", tabStr, algStr)
		}

		fmt.Fprintf(w, "%s\t},\n", tabStr)
		fmt.Fprintf(w, "%s},\n", tabStr)

	case *tls.UtlsExtendedMasterSecretExtension:
		fmt.Fprintf(w, "%s&%sUtlsExtendedMasterSecretExtension{},\n", tabStr, prefix)

	case *tls.UtlsGREASEExtension:
		fmt.Fprintf(w, "%s&%sUtlsGREASEExtension{},\n", tabStr, prefix)

	case *tls.UtlsPaddingExtension:
		fmt.Fprintf(w, "%s&%sUtlsPaddingExtension{\n", tabStr, prefix)

		if ext.PaddingLen != 0 {
			fmt.Fprintf(w, "%s\tPaddingLen: %d\n", tabStr, ext.PaddingLen)
		}
		if ext.WillPad != false {
			fmt.Fprintf(w, "%s\tWillPad: %t\n", tabStr, ext.WillPad)
		}

		if ext.GetPaddingLen != nil {
			if sameFunc(ext.GetPaddingLen, tls.BoringPaddingStyle) {
				fmt.Fprintf(w, "%s\tGetPaddingLen: %sBoringPaddingStyle,\n", tabStr, prefix)
			} else {
				return errors.New("unrecognized func in UtlsPaddingExtension.GetPaddingLen")
			}
		}

		fmt.Fprintf(w, "%s},\n", tabStr)

	default:
		return fmt.Errorf("unrecognized extension %T", e)
	}

	return nil
}

func printByteSlice(w io.Writer, b []byte, tabs int) {
	tabStr := ""
	for i := 0; i < tabs; i++ {
		tabStr += "\t"
	}

	for i, bite := range b {
		fmt.Fprintf(w, "%s%d,", tabStr, bite)
		if i != 0 && i%bytesPerLine == 0 {
			fmt.Fprintf(w, "\n")
		} else {
			fmt.Fprintf(w, " ")
		}
	}

	if len(b)%bytesPerLine != 0 {
		fmt.Fprintln(w)
	}
}

// Performs an identity check (*not* an equality check) on the two input functions. Returns true iff
// the two functions have the same underlying code pointer. This relies on implementation details of
// standard Go and is therefore a bit fragile. It should be okay for our use case though.
func sameFunc(f1, f2 any) bool {
	f1Val := reflect.ValueOf(f1)
	f2Val := reflect.ValueOf(f2)

	return f1Val.Pointer() == f2Val.Pointer()
}

var (
	versions = map[uint16]string{
		tls.VersionSSL30: "VersionSSL30",
		tls.VersionTLS10: "VersionTLS10",
		tls.VersionTLS11: "VersionTLS11",
		tls.VersionTLS12: "VersionTLS12",
		tls.VersionTLS13: "VersionTLS13",

		tls.GREASE_PLACEHOLDER: "GREASE_PLACEHOLDER",
	}

	cipherSuites = map[uint16]string{
		// TLS 1.0 - 1.2 cipher suites.
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA256:         "TLS_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305:    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305",
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305:  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305",

		// TLS 1.3 cipher suites.
		tls.TLS_AES_128_GCM_SHA256:       "TLS_AES_128_GCM_SHA256",
		tls.TLS_AES_256_GCM_SHA384:       "TLS_AES_256_GCM_SHA384",
		tls.TLS_CHACHA20_POLY1305_SHA256: "TLS_CHACHA20_POLY1305_SHA256",

		// TLS_FALLBACK_SCSV isn't a standard cipher suite but an indicator
		// that the client is doing version fallback. See RFC 7507.
		tls.TLS_FALLBACK_SCSV: "TLS_FALLBACK_SCSV",

		tls.OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   "OLD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		tls.OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: "OLD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",

		tls.DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: "DISABLED_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
		tls.DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:   "DISABLED_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
		tls.DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256:         "DISABLED_TLS_RSA_WITH_AES_256_CBC_SHA256",

		tls.FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256: "FAKE_OLD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
		tls.FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:           "FAKE_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",

		tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA:    "FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
		tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA:    "FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
		tls.FAKE_TLS_RSA_WITH_RC4_128_MD5:            "FAKE_TLS_RSA_WITH_RC4_128_MD5",
		tls.FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384: "FAKE_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
		tls.FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA:    "FAKE_TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
		tls.FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256: "FAKE_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
		tls.FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256: "FAKE_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
		tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV:   "FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV",

		tls.FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: "FAKE_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",

		tls.GREASE_PLACEHOLDER: "GREASE_PLACEHOLDER",
	}

	pskModes = map[uint8]string{
		tls.PskModePlain: "PskModePlain",
		tls.PskModeDHE:   "PskModeDHE",
	}

	renogotiations = map[tls.RenegotiationSupport]string{
		tls.RenegotiateNever:          "RenegotiateNever",
		tls.RenegotiateOnceAsClient:   "RenegotiateOnceAsClient",
		tls.RenegotiateFreelyAsClient: "RenegotiateFreelyAsClient",
	}

	signatureAlgorithms = map[tls.SignatureScheme]string{
		// RSASSA-PKCS1-v1_5 algorithms.
		tls.PKCS1WithSHA256: "PKCS1WithSHA256",
		tls.PKCS1WithSHA384: "PKCS1WithSHA384",
		tls.PKCS1WithSHA512: "PKCS1WithSHA512",

		// RSASSA-PSS algorithms with public key OID rsaEncryption.
		tls.PSSWithSHA256: "PSSWithSHA256",
		tls.PSSWithSHA384: "PSSWithSHA384",
		tls.PSSWithSHA512: "PSSWithSHA512",

		// ECDSA algorithms. Only constrained to a specific curve in TLS 1.3.
		tls.ECDSAWithP256AndSHA256: "ECDSAWithP256AndSHA256",
		tls.ECDSAWithP384AndSHA384: "ECDSAWithP384AndSHA384",
		tls.ECDSAWithP521AndSHA512: "ECDSAWithP521AndSHA512",

		// Legacy signature and hash algorithms for TLS 1.2.
		tls.PKCS1WithSHA1: "PKCS1WithSHA1",
		tls.ECDSAWithSHA1: "ECDSAWithSHA1",
	}

	curves = map[tls.CurveID]string{
		tls.CurveP256: "CurveP256",
		tls.CurveP384: "CurveP384",
		tls.CurveP521: "CurveP521",
		tls.X25519:    "X25519",

		tls.GREASE_PLACEHOLDER: "GREASE_PLACEHOLDER",
	}

	certCompressionAlgs = map[tls.CertCompressionAlgo]string{
		tls.CertCompressionZlib:   "CertCompressionZlib",
		tls.CertCompressionBrotli: "CertCompressionBrotli",
		tls.CertCompressionZstd:   "CertCompressionZstd",
	}
)
