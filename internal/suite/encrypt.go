package suite

import (
	"crypto/aes"
	"crypto/cipher"

	"github.com/tls-handshake/pkg/bytes"
)

func Encrypt(data, key, nonce []byte) (ciphertext []byte, err error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(a) // 128 bit AES
	if err != nil {
		return nil, err
	}
	nonce = bytes.PadSlice(nonce, 0x0, aesgcm.NonceSize())
	ciphertext = aesgcm.Seal(nil, nonce, data, nil)
	return ciphertext, nil
}