package tlstypes

import (
	"crypto/tls"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/pkg/rand"
)

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

func MakeClientHelloRecord() *Record {
	helloMsg := &ClientHelloMsg{
		Type:               ClientHelloMsgType,
		Length:             0, // will be auto calculated
		TLSVersion:         [2]byte{0x03, 0x01},
		SessionIDLen:       32,
		SessionID:          rand.CryptoRand(32), // session id is deprecated in TLS 1.3, but non zero value is set for compatibility
		CipherSuiteLen:     2,
		CipherSuite:        []CipherSuite{TLS_AES_128_GCM_SHA256},
		CompressionMethods: [2]byte{1, 0},
		ExtensionsLen:      5,
		ExtensionData:      []byte{0x00, 0x00, 0x00, 0x00, 0x00}, // not set yet
	}
	copy(helloMsg.Random[:], rand.CryptoRand(32))

	helloMsgBin := helloMsg.ToBinary()
	r := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: HandshakeRecord,
		Length:     uint16(len(helloMsgBin)),
		Data:       helloMsgBin,
	}

	return r
}

func MakeServerHelloRecord() *Record {
	helloMsg := &ServerHelloMsg{
		Type:               ServerHelloMsgType,
		Length:             0, // will be auto calculated
		TLSVersion:         [2]byte{0x03, 0x01},
		SessionIDLen:       32,
		SessionID:          rand.CryptoRand(32), // session id is deprecated in TLS 1.3, but non zero value is set for compatibility
		CipherSuite:        TLS_AES_128_GCM_SHA256,
		CompressionMethods: [1]byte{0},
		ExtensionsLen:      5,
		ExtensionData:      []byte{0x00, 0x00, 0x00, 0x00, 0x00}, // not set yet
	}
	copy(helloMsg.Random[:], rand.CryptoRand(32))

	helloMsgBin := helloMsg.ToBinary()
	r := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: HandshakeRecord,
		Length:     uint16(len(helloMsgBin)),
		Data:       helloMsgBin,
	}

	return r
}
