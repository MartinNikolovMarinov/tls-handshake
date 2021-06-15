package tlstypes

import (
	"bytes"
	"crypto/tls"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/internal/tls_types/extensions"
	"github.com/tls-handshake/pkg/rand"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

func MakeAlertRecord(a *Alert) *Record {
	common.AssertImpl(a != nil)
	abin := a.ToBinary()
	record := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: AlertRecord,
		Length:     uint16(len(abin)),
		Data:       abin,
	}
	return record
}

// The encryptedData does not include the record header. TODO: This does not follow the application recrod RFC 8446 and
// previous TLS protocols. It's missing Auth Tag which additionally protects the integrity of the encrypted data and the
// record header. With this implementation the record header could have been modified.
func MakeAppliactionRecord(encryptedData []byte) *Record {
	record := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: ApplicationRecord,
		Length:     uint16(len(encryptedData)),
		Data:       encryptedData,
	}
	return record
}

func MakeServerHelloRecord(serverHelloMsg *ServerHelloMsg) *Record {
	common.AssertImpl(serverHelloMsg != nil)
	data := serverHelloMsg.ToBinary()
	record := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: HandshakeRecord,
		Length:     uint16(len(data)),
		Data:       data,
	}
	return record
}

func MakeClientHelloRecord(clientHelloMsg *ClientHelloMsg) *Record {
	common.AssertImpl(clientHelloMsg != nil)
	data := clientHelloMsg.ToBinary()
	record := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: HandshakeRecord,
		Length:     uint16(len(data)),
		Data:       data,
	}
	return record
}

type KeyShareExtParams struct {
	CurveID tls.CurveID
	PubKey  []byte
}

type ClientHelloExtParams struct {
	KeyShareExtParams *KeyShareExtParams
}

type ServerHelloExtParams struct {
	KeyShareExtParams *KeyShareExtParams
}

func MakeClientHelloMessage(cfg *ClientHelloExtParams) *ClientHelloMsg {
	clientHelloMsg := &ClientHelloMsg{
		Type:               ClientHelloMsgType,
		Length:             0, // will be auto calculated
		TLSVersion:         [2]byte{0x03, 0x01},
		SessionIDLen:       32,
		SessionID:          rand.CryptoRand(32), // session id is deprecated in TLS 1.3, but non zero value is set for compatibility
		CipherSuiteLen:     2,
		CipherSuite:        []CipherSuite{TLS_AES_128_GCM_SHA256},
		CompressionMethods: [2]byte{1, 0},
	}
	copy(clientHelloMsg.Random[:], rand.CryptoRand(32))

	// Encode Extensions:
	if cfg != nil {
		extData := encodeClientHelloExtensions(cfg)
		clientHelloMsg.ExtensionsLen += uint16(len(extData))
		clientHelloMsg.ExtensionData = make([]byte, clientHelloMsg.ExtensionsLen)
		copy(clientHelloMsg.ExtensionData[:], extData)
	}

	return clientHelloMsg
}

func encodeClientHelloExtensions(cfg *ClientHelloExtParams) []byte {
	exts := encodeCommonExtensions(cfg.KeyShareExtParams)
	return exts
}

func MakeServerHelloMessage(cfg *ServerHelloExtParams) *ServerHelloMsg {
	serverHelloMsg := &ServerHelloMsg{
		Type:               ServerHelloMsgType,
		Length:             0, // will be auto calculated
		TLSVersion:         [2]byte{0x03, 0x01},
		SessionIDLen:       32,
		SessionID:          rand.CryptoRand(32), // session id is deprecated in TLS 1.3, but non zero value is set for compatibility
		CipherSuite:        TLS_AES_128_GCM_SHA256,
		CompressionMethods: [1]byte{0},
	}
	copy(serverHelloMsg.Random[:], rand.CryptoRand(32))

	// Encode Extensions:
	if cfg != nil {
		extData := encodeServerHelloExtensions(cfg)
		serverHelloMsg.ExtensionsLen += uint16(len(extData))
		serverHelloMsg.ExtensionData = make([]byte, serverHelloMsg.ExtensionsLen)
		copy(serverHelloMsg.ExtensionData[:], extData)
	}

	return serverHelloMsg
}

func encodeServerHelloExtensions(cfg *ServerHelloExtParams) []byte {
	exts := encodeCommonExtensions(cfg.KeyShareExtParams)
	return exts
}

func encodeCommonExtensions(ksep *KeyShareExtParams) []byte {
	var (
		buf  bytes.Buffer
		err error
	)

	if ksep != nil {
		kse := &extensions.KeyShareExtension{
			Type:            extensions.KeyShareType,
			KeyShareDataLen: 0, // does not seem to matters
			CurveID:         ksep.CurveID,
			PubKeyBytesLen:  uint16(len(ksep.PubKey)),
			PublicKey:       ksep.PubKey,
		}
		kse.ExtensionLen = kse.PubKeyBytesLen + typesizes.Uint16Bytes*3
		_, err = buf.Write(kse.ToBinary())
		common.AssertImpl(err == nil)
	}

	sv := &extensions.SupportedVersions{
		Type:          extensions.SupporteVersionsType,
		ExtensionLen:  3,
		TLSVersionLen: 2,
		TLSVersion:    tls.VersionTLS13,
	}
	_, err = buf.Write(sv.ToBinary())
	common.AssertImpl(err == nil)
	return buf.Bytes()
}