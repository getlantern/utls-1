package tls

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"io"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/cryptobyte"
)

// Only implemented client-side.
// https://datatracker.ietf.org/doc/html/rfc8879
type compressedCertificateMessage struct {
	raw []byte

	algorithm                    uint16
	uncompressedLength           uint32 // uint24
	compressedCertificateMessage []byte
}

func (m *compressedCertificateMessage) marshal() []byte {
	if m.raw != nil {
		return m.raw
	}

	var b cryptobyte.Builder
	b.AddUint8(typeCompressedCertificate)
	b.AddUint16(m.algorithm)
	b.AddUint24(m.uncompressedLength)
	b.AddBytes(m.compressedCertificateMessage)

	m.raw = b.BytesOrPanic()
	return m.raw
}

func (m *compressedCertificateMessage) unmarshal(data []byte) bool {
	*m = compressedCertificateMessage{raw: data}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.algorithm) ||
		!s.ReadUint24(&m.uncompressedLength) ||
		!readUint24LengthPrefixed(&s, &m.compressedCertificateMessage) {
		return false
	}
	return true
}

func (m compressedCertificateMessage) decompress() (*certificateMsgTLS13, error) {
	// TODO: randomly get 'error decoding message' when connecting to swimswam.com (probably
	// doesn't originate in this function). Also happening with google.com...

	// TODO: check whether these errors need to result in specific calls to setErrorLocked

	var decompressed io.Reader
	compressed := bytes.NewReader(m.compressedCertificateMessage)

	switch CertCompressionAlgo(m.algorithm) {
	case CertCompressionBrotli:
		decompressed = brotli.NewReader(compressed)

	case CertCompressionZlib:
		rc, err := zlib.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("failed to open zlib reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	case CertCompressionZstd:
		rc, err := zstd.NewReader(compressed)
		if err != nil {
			return nil, fmt.Errorf("failed to open zstd reader: %w", err)
		}
		defer rc.Close()
		decompressed = rc

	default:
		return nil, fmt.Errorf("unsupported algorithm (%d)", m.algorithm)
	}

	rawCertMsg, err := io.ReadAll(io.LimitReader(decompressed, int64(m.uncompressedLength)))
	if err != nil {
		return nil, err
	}
	rawCertMsg = append([]byte{typeCertificate, 0, 0, 0}, rawCertMsg...)
	certMsg := new(certificateMsgTLS13)
	if !certMsg.unmarshal(rawCertMsg) {
		return nil, errors.New("failed to parse")
	}
	return certMsg, nil
}
