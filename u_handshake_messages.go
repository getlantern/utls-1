package tls

import (
	"golang.org/x/crypto/cryptobyte"
)

// TODO: randomly get 'error decoding message' when connecting to swimswam.com (probably
// doesn't originate in this function). Also happening with google.com...

// Only implemented client-side, for server certificates.
// Alternate certificate message formats (https://datatracker.ietf.org/doc/html/rfc7250) are not
// supported.
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
