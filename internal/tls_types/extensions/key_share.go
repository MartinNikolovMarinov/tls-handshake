package extensions

import (
	"crypto/tls"
	"errors"

	"github.com/tls-handshake/internal/common"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

type KeyShareExtension struct {
	Type            ExtensionType
	ExtensionLen    uint16 // ignore these
	KeyShareDataLen uint16 // ignore these
	CurveID         tls.CurveID
	PubKeyBytesLen  uint16
	PublicKey       []byte
}

func ParseKeyShareExtension(buf []byte) (ksext *KeyShareExtension, err error) {
	wi := 0 // write index
	ksext = &KeyShareExtension{}

	ksext.Type, err = ParseExtensionType(buf)
	if err != nil {
		return nil, err
	}
	if ksext.Type != KeyShareType {
		return nil, errors.New("not a key share extension type")
	}
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("key share extension has invalid format")
	}
	ksext.ExtensionLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
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
	if wi != (int(ksext.PubKeyBytesLen) + int(typesizes.Uint16Bytes)*5) {
		return nil, errors.New("key share extension has invalid public key length")
	}
	if wi != ksext.GetFullExtLen() {
		return nil, errors.New("key share extension has invalid extension length")
	}

	return ksext, nil
}

func (kse *KeyShareExtension) ToBinary() []byte {
	common.AssertImpl(kse != nil)
	raw := make([]byte, 0, kse.GetFullExtLen())
	raw = append(raw, byte(kse.Type>>8), byte(kse.Type))
	raw = append(raw, byte(kse.ExtensionLen>>8), byte(kse.ExtensionLen))
	raw = append(raw, byte(kse.KeyShareDataLen>>8), byte(kse.KeyShareDataLen))
	raw = append(raw, byte(kse.CurveID>>8), byte(kse.CurveID))
	raw = append(raw, byte(kse.PubKeyBytesLen>>8), byte(kse.PubKeyBytesLen))
	raw = append(raw, kse.PublicKey[:]...)
	return raw
}

func (kse *KeyShareExtension) GetType() ExtensionType { return kse.Type }

func (kse *KeyShareExtension) GetFullExtLen() int {
	full := int(kse.ExtensionLen) + (typesizes.Uint16Bytes * 2)
	return full
}
