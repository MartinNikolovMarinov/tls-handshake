package suite

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/tls-handshake/pkg/bytes"
)

func Decrypt(data, key, nonce []byte) (plain []byte, err error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}
	nonce = bytes.PadSlice(nonce, 0x0, aesgcm.NonceSize())
	if plain, err = aesgcm.Open(nil, nonce, data, nil); err != nil {
		return nil, err
	}
	return plain, nil
}