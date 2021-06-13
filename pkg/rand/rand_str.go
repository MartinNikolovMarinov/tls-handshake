package rand

import (
	crand "crypto/rand"
	mrand "math/rand"
	"time"

	"github.com/tls-handshake/internal/common"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *mrand.Rand = mrand.New(
	mrand.NewSource(time.Now().UnixNano()))

func GenString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

const maxRandomBytes = 10000 // never going to need more than that, anything above is an error.

func CryptoRand(length int) []byte {
	common.AssertImpl(0 < length && length < maxRandomBytes)
	b := make([]byte, length)
	_, _ = crand.Read(b)
	return b
}