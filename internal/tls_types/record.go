package tlstypes

import (
	"crypto/tls"
	"errors"
	"io"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/pkg/streams"
)

type RecordType uint8

const (
	AlertRecord     RecordType = 0x15
	HandshakeRecord RecordType = 0x16

	// This value is the length of the plaintext of a protected record. The value includes the content type and padding
	// added in TLS 1.3 (that is, the complete length of TLSInnerPlaintext). TLS 1.3 uses a limit of 2^14+1 octets.
	MaxSizeOfPlaintextRecord int = 16385 // maxPlaintext
)

type Record struct {
	RecordType RecordType
	TLSVersion uint16
	Length     uint16 // bytes in rest of the handshake message
	Data       []byte
}

func MakeAlertRecord(a *Alert) *Record {
	common.AssertImpl(a != nil)
	abin := a.ToBinary()
	r := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: AlertRecord,
		Length:     uint16(len(abin)),
		Data:       abin,
	}

	return r
}

func ParseRecord(raw []byte) (*Record, error) {
	if len(raw) < int(RecordHeaderByteSize) {
		return nil, errors.New("unsupported record header byte size")
	}

	ret := &Record{}
	switch RecordType(raw[0]) {
	case HandshakeRecord:
		ret.RecordType = HandshakeRecord
	case AlertRecord:
		ret.RecordType = AlertRecord
	default:
		return nil, errors.New("unsupported record type")
	}

	ret.TLSVersion = (uint16(raw[1]) << 8) + uint16(raw[2])
	switch ret.TLSVersion {
	case tls.VersionTLS13:
		ret.TLSVersion = uint16(tls.VersionTLS13)
	default:
		return nil, errors.New("unsupported version of TLS")
	}

	ret.Length = (uint16(raw[3]) << 8) + uint16(raw[4])
	if int(ret.Length) > MaxSizeOfPlaintextRecord {
		return nil, errors.New("record length exceeds the maximum for a record")
	}
	if len(raw) < (int(RecordHeaderByteSize) + int(ret.Length)) {
		return nil, errors.New("invalid record length")
	}

	ret.Data = make([]byte, ret.Length)
	copy(ret.Data[:], raw[RecordHeaderByteSize:])
	return ret, nil
}

func (rh *Record) HeaderToBinary() []byte {
	common.AssertImpl(rh != nil)
	raw := make([]byte, RecordHeaderByteSize)
	raw[0] = byte(rh.RecordType)
	raw[1] = byte(rh.TLSVersion >> 8)
	raw[2] = byte(rh.TLSVersion)
	raw[3] = byte(rh.Length >> 8)
	raw[4] = byte(rh.Length)
	return raw
}

func (rh *Record) ToBinary() []byte {
	common.AssertImpl(rh != nil)
	hbin := rh.HeaderToBinary()
	raw := make([]byte, len(hbin)+len(rh.Data))
	copy(raw[:], hbin[:])
	copy(raw[len(hbin):], rh.Data[:])
	return raw
}

func (rh *Record) WriteTo(w io.Writer) (int64, error) {
	common.AssertImpl(rh != nil)
	data := rh.ToBinary()
	err := streams.WriteAllBytes(w, data)
	return int64(len(data)), err
}
