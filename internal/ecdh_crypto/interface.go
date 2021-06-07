package ecdhcrypto

import "crypto/ecdsa"

type ECDHCrypto interface {
	GenerateKey(cs ECDHCurveSize) (*ecdsa.PrivateKey, error)
}