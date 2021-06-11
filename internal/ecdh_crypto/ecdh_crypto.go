package ecdhcrypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

const (
	privateKeyPemBlockType = "PRIVATE KEY"
)

var (
	UnsupportedPubKeyErr      = errors.New("unsupported public key type")
	UnsupportedPrivateKeyErr  = errors.New("unsupported private key type")
	UnmarshalPubKeyFailedErr  = errors.New("failed to unmarshal public key")
	InvalidPrivateKeyBlockErr = errors.New("invalid private key pem block")
)

type ECDHCrypto struct {
	curve elliptic.Curve
	rnd   io.Reader
}

func NewECDHCrypto(curve elliptic.Curve, rnd io.Reader) *ECDHCrypto { // FIXME: return an interface here !
	ret := &ECDHCrypto{curve: curve, rnd: rnd}
	return ret
}

func (e *ECDHCrypto) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(e.curve, e.rnd)
	return priv, priv.Public(), err
}

func (e *ECDHCrypto) MarshalPubKey(p crypto.PublicKey) ([]byte, error) {
	pub, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, UnsupportedPubKeyErr
	}

	return elliptic.Marshal(e.curve, pub.X, pub.Y), nil
}

func (e *ECDHCrypto) UnmarshalPubKey(out []byte) (crypto.PublicKey, error) {
	x, y := elliptic.Unmarshal(e.curve, out)
	if x == nil || y == nil {
		return nil, UnmarshalPubKeyFailedErr
	}
	key := &ecdsa.PublicKey{
		Curve: e.curve,
		X:     x,
		Y:     y,
	}
	return key, nil
}

func (e *ECDHCrypto) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, UnsupportedPrivateKeyErr
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, UnsupportedPubKeyErr
	}

	x, _ := e.curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes(), nil
}

// EncodePrivateKeyToPKCS encodes a private key to PKCS.
// PKCS #8 is a standard syntax for storing private key information. See RFC 5958.
// This data can be saved to a file.
// Function does NOT use a passphrase.
func (e *ECDHCrypto) EncodePrivateKeyToPKCS(privKey crypto.PrivateKey) ([]byte, error) {
	pkcsBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, err
	}
	ret := pem.EncodeToMemory(&pem.Block{Type: privateKeyPemBlockType, Bytes: pkcsBytes})
	return ret, nil
}

// DecodePrivateKeyFromPKCS decodes a private key from a PKCS encoded input data.
// Works only if pem block type is privateKeyPemBlockType and there is exactly one pem block in
// the PKCS encoded input data.
// This data can be read from a file.
func (e *ECDHCrypto) DecodePrivateKeyFromPKCS(data []byte) (crypto.PrivateKey, error) {
	p, rest := pem.Decode(data)
	if (len(rest) > 0) || (p == nil) || (p.Type != privateKeyPemBlockType) {
		return nil, InvalidPrivateKeyBlockErr
	}
	pKey, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	return pKey, nil
}