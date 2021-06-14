package suite

import (
	"crypto/sha256"
	"hash"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
)

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

// // nextTrafficSecret generates the next traffic secret, given the current one,
// // according to RFC 8446, Section 7.2.
// func (c *CipherSuiteTLS13) nextTrafficSecret(trafficSecret []byte) []byte {
// 	return c.ExpandLabel(trafficSecret, trafficUpdateLabel, nil, c.hash.Size())
// }

// // trafficKey generates traffic keys according to RFC 8446, Section 7.3.
// func (c *CipherSuiteTLS13) trafficKey(trafficSecret []byte) (key, iv []byte) {
// 	key = c.ExpandLabel(trafficSecret, "key", nil, c.keyLen)
// 	iv = c.ExpandLabel(trafficSecret, "iv", nil, aeadNonceLength)
// 	return
// }

// // finishedHash generates the Finished verify_data or PskBinderEntry according
// // to RFC 8446, Section 4.4.4. See sections 4.4 and 4.2.11.2 for the baseKey
// // selection.
// func (c *CipherSuiteTLS13) finishedHash(baseKey []byte, transcript hash.Hash) []byte {
// 	finishedKey := c.ExpandLabel(baseKey, "finished", nil, c.hash.Size())
// 	verifyData := hmac.New(c.hash.New, finishedKey)
// 	verifyData.Write(transcript.Sum(nil))
// 	return verifyData.Sum(nil)
// }

// // exportKeyingMaterial implements RFC5705 exporters for TLS 1.3 according to
// // RFC 8446, Section 7.5.
// func (c *CipherSuiteTLS13) exportKeyingMaterial(masterSecret []byte, transcript hash.Hash) func(string, []byte, int) ([]byte, error) {
// 	expMasterSecret := c.DeriveSecret(masterSecret, exporterLabel, transcript)
// 	return func(label string, context []byte, length int) ([]byte, error) {
// 		secret := c.DeriveSecret(expMasterSecret, label, nil)
// 		h := c.hash.New()
// 		h.Write(context)
// 		return c.ExpandLabel(secret, "exporter", h.Sum(nil), length), nil
// 	}
// }
