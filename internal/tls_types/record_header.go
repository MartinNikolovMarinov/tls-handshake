package tlstypes

import (
	"crypto/tls"
	"errors"
)

type RecordType uint8

const (
	HandshakeRecord RecordType = 0x16
)

type RecordHeader struct {
	RecordType      RecordType
	TLSVersion      uint16
	BytesInHandsake uint16 // bytes in rest of the handshake message
}

func ParseRecordHeader(raw [5]byte) (RecordHeader, error) {
	var ret RecordHeader

	switch RecordType(raw[0]) {
	case HandshakeRecord:
		ret.RecordType = HandshakeRecord
	default:
		return ret, errors.New("unsupported record type")
	}

	ret.TLSVersion = (uint16(raw[1]) << 8) + uint16(raw[2])
	switch ret.TLSVersion {
	case tls.VersionTLS13:
		ret.TLSVersion = uint16(tls.VersionTLS13)
	default:
		return ret, errors.New("unsupported version of TLS")
	}

	ret.BytesInHandsake = (uint16(raw[3]) << 8) + uint16(raw[4])
	return ret, nil
}
