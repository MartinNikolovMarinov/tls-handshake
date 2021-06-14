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

	"github.com/tls-handshake/internal/common"
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

func GenerateKey(curve elliptic.Curve, rnd io.Reader) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	priv, err := ecdsa.GenerateKey(curve, rnd)
	return priv, priv.Public().(*ecdsa.PublicKey), err
}

func MarshalPubKey(pub *ecdsa.PublicKey) []byte {
	common.AssertImpl(pub != nil)
	return elliptic.Marshal(pub.Curve, pub.X, pub.Y)
}

func UnmarshalPubKey(curve elliptic.Curve, out []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(curve, out)
	if x == nil || y == nil {
		return nil, UnmarshalPubKeyFailedErr
	}
	key := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	return key, nil
}

func GenerateSharedSecret(priv *ecdsa.PrivateKey, pub *ecdsa.PublicKey) ([]byte, error) {
	common.AssertImpl(priv != nil && pub != nil && priv.Curve == pub.Curve)
	x, _ := priv.Curve.ScalarMult(pub.X, pub.Y, priv.D.Bytes())
	return x.Bytes(), nil
}

// EncodePrivateKeyToPKCS encodes a private key to PKCS.
// PKCS #8 is a standard syntax for storing private key information. See RFC 5958.
// This data can be saved to a file.
// Function does NOT use a passphrase.
func EncodePrivateKeyToPKCS(priv *ecdsa.PrivateKey) ([]byte, error) {
	common.AssertImpl(priv != nil)
	pkcsBytes, err := x509.MarshalPKCS8PrivateKey(priv)
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
func DecodePrivateKeyFromPKCS(data []byte) (crypto.PrivateKey, error) {
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
