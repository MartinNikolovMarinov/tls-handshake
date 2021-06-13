package tlstypes

import (
	"crypto/tls"
	"errors"

	"github.com/tls-handshake/internal/common"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

type ExtensionType uint16

const (
	KeyShare ExtensionType = 0x33
)

type KeyShareExtension struct {
	Type            ExtensionType
	ExtentionLen    uint16 // ignore these
	KeyShareDataLen uint16 // ignore these
	CurveID         tls.CurveID
	PubKeyBytesLen  uint16
	PublicKey       []byte
}

func ParseKeyShareExtension(buf []byte) (ksext *KeyShareExtension, err error) {
	wi := 0 // write index
	ksext = &KeyShareExtension{}

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.Type = (ExtensionType(buf[wi]) << 8) + ExtensionType(buf[wi+1])
	if ksext.Type != KeyShare {
		return nil, errors.New("not a key share extension type")
	}
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.ExtentionLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.KeyShareDataLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.CurveID = (tls.CurveID(buf[wi]) << 8) + tls.CurveID(buf[wi+1])
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.PubKeyBytesLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(ksext.PubKeyBytesLen) {
		return nil, errors.New("key share extension invalid pub key length")
	}
	ksext.PublicKey = make([]byte, ksext.PubKeyBytesLen)
	wi += copy(ksext.PublicKey[:], buf[wi:])

	// Final sanity check:
	common.AssertImpl(wi-typesizes.Uint16Bytes*5 == int(ksext.PubKeyBytesLen))

	return ksext, nil
}

func (hm *KeyShareExtension) ToBinary() []byte {
	common.AssertImpl(hm != nil)
	raw := make([]byte, 0)
	raw = append(raw, byte(hm.Type>>8), byte(hm.Type))
	raw = append(raw, byte(hm.ExtentionLen>>8), byte(hm.ExtentionLen))
	raw = append(raw, byte(hm.KeyShareDataLen>>8), byte(hm.KeyShareDataLen))
	raw = append(raw, byte(hm.CurveID>>8), byte(hm.CurveID))
	raw = append(raw, byte(hm.PubKeyBytesLen>>8), byte(hm.PubKeyBytesLen))
	raw = append(raw, hm.PublicKey[:]...)
	return raw
}
