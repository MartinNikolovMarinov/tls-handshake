package ecdh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
)

var DefaultCurve = elliptic.P256()
const DefaultCurveID = tls.CurveP256

const (
	privateKeyPemBlockType = "PRIVATE KEY"
)

var (
	UnsupportedPubKeyErr      = errors.New("unsupported public key type")
	UnsupportedPrivateKeyErr  = errors.New("unsupported private key type")
	UnmarshalPubKeyFailedErr  = errors.New("failed to unmarshal public key")
	InvalidPrivateKeyBlockErr = errors.New("invalid private key pem block")
)

type ECDHKeyManager struct {
	curve elliptic.Curve
	rnd   io.Reader
}

func NewManager(curve elliptic.Curve, rnd io.Reader) *ECDHKeyManager { // FIXME: return an interface here !
	if curve == nil {
		curve = DefaultCurve
	}
	ret := &ECDHKeyManager{curve: curve, rnd: rnd}
	return ret
}

func (m *ECDHKeyManager) GenerateKey() (crypto.PrivateKey, crypto.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(m.curve, m.rnd)
	return priv, priv.Public(), err
}

func (m *ECDHKeyManager) MarshalPubKey(p crypto.PublicKey) ([]byte, error) {
	pub, ok := p.(*ecdsa.PublicKey)
	if !ok {
		return nil, UnsupportedPubKeyErr
	}

	return elliptic.Marshal(m.curve, pub.X, pub.Y), nil
}

func (m *ECDHKeyManager) UnmarshalPubKey(out []byte) (crypto.PublicKey, error) {
	x, y := elliptic.Unmarshal(m.curve, out)
	if x == nil || y == nil {
		return nil, UnmarshalPubKeyFailedErr
	}
	key := &ecdsa.PublicKey{
		Curve: m.curve,
		X:     x,
		Y:     y,
	}
	return key, nil
}

func (m *ECDHKeyManager) GenerateSharedSecret(privKey crypto.PrivateKey, pubKey crypto.PublicKey) ([]byte, error) {
	priv, ok := privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, UnsupportedPrivateKeyErr
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, UnsupportedPubKeyErr
	}

	x, _ := m.curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes(), nil
}

// EncodePrivateKeyToPKCS encodes a private key to PKCS.
// PKCS #8 is a standard syntax for storing private key information. See RFC 5958.
// This data can be saved to a file.
// Function does NOT use a passphrase.
func (m *ECDHKeyManager) EncodePrivateKeyToPKCS(privKey crypto.PrivateKey) ([]byte, error) {
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
func (m *ECDHKeyManager) DecodePrivateKeyFromPKCS(data []byte) (crypto.PrivateKey, error) {
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
