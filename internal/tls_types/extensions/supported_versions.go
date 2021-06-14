package extensions

import (
	"crypto/tls"
	"errors"

	"github.com/tls-handshake/internal/common"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

// 0 03 - 0x3 (3) bytes of "Supported Versions" extension data follows
// 02 - 0x2 (2) bytes of TLS versions follow
// 03 04 - assigned value for TLS 1.3

type SupportedVersions struct {
	Type          ExtensionType
	ExtensionLen  uint16
	TLSVersionLen uint8
	TLSVersion    uint16
}

func ParseSupporteVersionsExtension(buf []byte) (supver *SupportedVersions, err error) {
	supver = &SupportedVersions{}
	wi := 0 // write index

	supver.Type, err = ParseExtensionType(buf)
	if err != nil {
		return nil, err
	}
	if supver.Type != SupporteVersionsType {
		return nil, errors.New("not a supported version extension type")
	}
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("supported version extension has invalid format")
	}
	supver.ExtensionLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	wi += int(typesizes.Uint16Bytes)

	if len(buf[wi:]) < int(typesizes.Uint8Bytes) {
		return nil, errors.New("supported version extension has invalid format")
	}
	supver.TLSVersionLen = uint8(buf[wi])
	wi += int(typesizes.Uint8Bytes)

	if len(buf[wi:]) < int(typesizes.Uint16Bytes) {
		return nil, errors.New("supported version extension has invalid format")
	}
	supver.TLSVersion = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	switch supver.TLSVersion {
	case tls.VersionTLS13:
		supver.TLSVersion = uint16(tls.VersionTLS13)
	default:
		return nil, errors.New("unsupported version of TLS")
	}
	wi += int(typesizes.Uint16Bytes)

	// Need to check extension length:
	if wi != supver.GetFullExtLen() {
		return nil, errors.New("unsupported version has invalid extension length")
	}

	return supver, nil
}

func (sve *SupportedVersions) ToBinary() []byte {
	common.AssertImpl(sve != nil)
	raw := make([]byte, 0, sve.GetFullExtLen())
	raw = append(raw, byte(sve.Type>>8), byte(sve.Type))
	raw = append(raw, byte(sve.ExtensionLen>>8), byte(sve.ExtensionLen))
	raw = append(raw, byte(sve.TLSVersionLen))
	raw = append(raw, byte(sve.TLSVersion>>8), byte(sve.TLSVersion))
	return raw
}

func (sve *SupportedVersions) GetType() ExtensionType { return sve.Type }

func (sve *SupportedVersions) GetFullExtLen() int {
	full := int(sve.ExtensionLen)+(int(typesizes.Uint16Bytes)*2)
	return full
}
