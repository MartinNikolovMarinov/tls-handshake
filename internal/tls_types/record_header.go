package tlstypes

import (
	"crypto/tls"
	"errors"

	"github.com/tls-handshake/internal/common"
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

func ParseRecordHeader(raw []byte) (RecordHeader, error) {
	var ret RecordHeader
	if len(raw) != int(RecordHeaderByteSize) {
		return ret, errors.New("unsupported record header byte size")
	}

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

func MarshalRecordHeader(rh *RecordHeader) []byte {
	if rh == nil {
		panic(common.ImplementationErr)
	}
	raw := make([]byte, RecordHeaderByteSize)
	raw[0] = byte(rh.RecordType)
	raw[1] = byte(rh.TLSVersion >> 8)
	raw[2] = byte(rh.TLSVersion)
	raw[3] = byte(rh.BytesInHandsake >> 8)
	raw[4] = byte(rh.BytesInHandsake)
	return raw
}