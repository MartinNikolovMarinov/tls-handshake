package extensions

import (
	"errors"
	"math"

	"github.com/tls-handshake/internal/common"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

type ExtensionType uint16

const (
	NotSetType           ExtensionType = math.MaxUint16
	KeyShareType         ExtensionType = 0x33
	SupporteVersionsType ExtensionType = 0x2b
)

type Extension interface {
	GetType() ExtensionType
	ToBinary() []byte
	GetFullExtLen() int
}

func ParseExtensions(buf []byte, byteLen uint16) (exts []Extension, err error) {
	var t ExtensionType
	var ri int // read index
	exts = make([]Extension, 0)
	for ri = 0; ri < int(byteLen); {
		t, err = ParseExtensionType(buf[ri:])
		if err != nil {
			return nil, err
		}

		var ex Extension
		switch t {
		case KeyShareType:
			ex, err = ParseKeyShareExtension(buf[ri:])
		case SupporteVersionsType:
			ex, err = ParseSupporteVersionsExtension(buf[ri:])
		default:
			err = errors.New("unsupported extension")
		}

		if err != nil {
			return nil, err
		}
		exts = append(exts, ex)
		ri += ex.GetFullExtLen()
	}

	common.AssertImpl(ri == len(buf))
	common.AssertImpl(ri == int(byteLen))

	return exts, nil
}

func ParseExtensionType(buf []byte) (ExtensionType, error) {
	if len(buf) < int(typesizes.Uint16Bytes) {
		return NotSetType, errors.New("extension type is invalid or not supported")
	}
	t := (ExtensionType(buf[0]) << 8) + ExtensionType(buf[1])
	return t, nil
}

func FindExtension(exts []Extension, exType ExtensionType) (ext Extension) {
	for i := 0; i < len(exts); i++ {
		if exts[i].GetType() == exType {
			return exts[i]
		}
	}
	return nil
}
