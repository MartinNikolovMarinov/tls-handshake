package ecdhcrypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"io"
)

type ECDHCurveSize string

const (
	Secp256r1 ECDHCurveSize = "secp256r1"
	Secp384r1 ECDHCurveSize = "secp384r1"
	Secp521r1 ECDHCurveSize = "secp521r1"
)

type ecdhCrypto struct {
}

func NewECDHCrypto() ECDHCrypto {
	return &ecdhCrypto{}
}

func (ec *ecdhCrypto) GenerateKey(cs ECDHCurveSize) (*ecdsa.PrivateKey, error) {
	var pubkeyCurve elliptic.Curve

	switch cs {
	case Secp256r1:
		pubkeyCurve = elliptic.P256()
	case Secp384r1:
		pubkeyCurve = elliptic.P384()
	case Secp521r1:
		pubkeyCurve = elliptic.P521()
	default:
		return nil, errors.New("Unsupported ECDHCurveSize")
	}

	var err error
	privatekey := new(ecdsa.PrivateKey)
	if privatekey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader); err != nil {
		return nil, err
	}

	return privatekey, nil
}


func (ec *ecdhCrypto) Sign(privateKey *ecdsa.PrivateKey, reader io.Reader) (error) {
	// TODO:
	// h := md5.New()
	// r := big.NewInt(0)
	// s := big.NewInt(0)

	// io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
	// signhash := h.Sum(nil)
	// r, s, err := ecdsa.Sign(rand.Reader, privateKey, signhash)
	// if err != nil {
	// 	return err
	// }

	// signature := r.Bytes()
	// signature = append(signature, s.Bytes()...)

	// fmt.Printf("Signature : %x\n", signature)
	return nil
}

// TODO:
// Sign ecdsa style

// // Verify
// verifystatus := ecdsa.Verify(&pubkey, signhash, r, s)
// fmt.Println(verifystatus) // should be true
