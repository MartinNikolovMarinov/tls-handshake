package suite

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

// NOTE: taken from the golang core tls library

const (
	// ResumptionBinderLabel         = "res binder"
	ClientHandshakeTrafficLabel   = "c hs traffic"
	ServerHandshakeTrafficLabel   = "s hs traffic"
	ClientApplicationTrafficLabel = "c ap traffic"
	ServerApplicationTrafficLabel = "s ap traffic"
	KeyLabel                      = "key"
	IVLabel                       = "iv"
	// ResumptionLabel               = "res master"
	// TrafficUpdateLabel            = "traffic upd"
)

// ExpandLabel implements HKDF-Expand-Label from RFC 8446, Section 7.1.
func ExpandLabel(secret []byte, label string, context []byte, length int) []byte {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		panic("tls: HKDF-Expand-Label invocation failed unexpectedly")
	}
	return out
}

// DeriveSecret implements Derive-Secret from RFC 8446, Section 7.1.
func DeriveSecret(secret []byte, label string, transcript hash.Hash) []byte {
	if transcript == nil {
		transcript = sha256.New()
	}
	return ExpandLabel(secret, label, transcript.Sum(nil), sha256.New().Size())
}

// Extract implements HKDF-Extract with the cipher suite hash.
func Extract(newSecret, currentSecret []byte) []byte {
	if newSecret == nil {
		newSecret = make([]byte, sha256.New().Size())
	}
	return hkdf.Extract(sha256.New, newSecret, currentSecret)
}