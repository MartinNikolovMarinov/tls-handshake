package ecdh

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"testing"
)


func TestGenerateSharedSecret(t *testing.T) {
	var privKey1, privKey2 *ecdsa.PrivateKey
	var pubKey1, pubKey2 *ecdsa.PublicKey
	var pubKey1Buf, pubKey2Buf []byte
	var err error
	var secret1, secret2 []byte

	privKey1, pubKey1, err = GenerateKey(DefaultCurve, rand.Reader)
	if err != nil {
		t.Error(err)
	}
	privKey2, pubKey2, err = GenerateKey(DefaultCurve, rand.Reader)
	if err != nil {
		t.Error(err)
	}

	pubKey1Buf = MarshalPubKey(pubKey1)
	pubKey2Buf = MarshalPubKey(pubKey2)

	pubKey1, err = UnmarshalPubKey(DefaultCurve, pubKey1Buf)
	if err != nil {
		t.Error(err)
	}
	pubKey2, err = UnmarshalPubKey(DefaultCurve, pubKey2Buf)
	if err != nil {
		t.Error(err)
	}

	secret1, err = GenerateSharedSecret(privKey1, pubKey2)
	if err != nil {
		t.Error(err)
	}
	secret2, err = GenerateSharedSecret(privKey2, pubKey1)
	if err != nil {
		t.Error(err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatalf("The two shared keys: %d, %d do not match", secret1, secret2)
	}
}