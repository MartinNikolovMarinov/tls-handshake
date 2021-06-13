package tlstypes

import (
	"errors"

	"github.com/tls-handshake/internal/common"
	typesizes "github.com/tls-handshake/pkg/type_sizes"
)

type ClientHelloMsg struct {
	Type               HandshakeMsgType
	Length             uint
	TLSVersion         [VersionByteSize]byte // this one is hardcoded to tls 1.2, ignore it
	Random             [RandomByteSize]byte
	SessionIDLen       uint8
	SessionID          []byte
	CipherSuiteLen     uint16
	CipherSuite        []CipherSuite
	CompressionMethods [2]byte
	ExtensionsLen      uint16
	ExtensionData      []byte
}

func ParseClientHelloMsg(buf []byte) (hm *ClientHelloMsg, err error) {
	if len(buf) < int(HandshakeHeaderByteSize) {
		// must be able to, at least, read the HandshakeHeader
		return nil, errors.New("unsupported handshake message size")
	}

	wi := 0 // write index
	hm = &ClientHelloMsg{}

	// Handshake Header:
	hm.Type = HandshakeMsgType(buf[wi])
	if hm.Type != ClientHelloMsgType {
		return nil, errors.New("not a client hello handshake message")
	}
	hm.Length = uint(buf[wi+1])<<16 + uint(buf[wi+2])<<8 + uint(buf[wi+3])
	wi += int(HandshakeHeaderByteSize)
	if hm.Length > uint(len(buf[wi:])) {
		return nil, errors.New("client hello message has invalid length")
	}

	// TLSVersion:
	if len(buf[wi:]) < len(hm.TLSVersion[:]) {
		return nil, errors.New("client hello message has invalid format")
	}
	wi += copy(hm.TLSVersion[:], buf[wi:])

	// Random:
	if len(buf[wi:]) < len(hm.Random[:]) {
		return nil, errors.New("client hello message has invalid format")
	}
	wi += copy(hm.Random[:], buf[wi:])

	// SessionID:
	if len(buf[wi:]) < typesizes.Uint8Bytes {
		return nil, errors.New("client hello message has invalid format")
	}
	hm.SessionIDLen = uint8(buf[wi])
	wi += typesizes.Uint8Bytes
	if len(buf[wi:]) < int(hm.SessionIDLen) {
		return nil, errors.New("client hello message has invalid sessionID length")
	}
	hm.SessionID = make([]byte, hm.SessionIDLen)
	wi += copy(hm.SessionID[:], buf[wi:])

	// CipherSuites:
	if len(buf[wi:]) < typesizes.Uint16Bytes {
		return nil, errors.New("client hello message has invalid format")
	}
	hm.CipherSuiteLen = uint16(buf[wi])<<8 + uint16(buf[wi+1])
	wi += typesizes.Uint16Bytes
	if len(buf[wi:]) < int(hm.CipherSuiteLen) {
		return nil, errors.New("client hello message has invalid cipher suite length")
	}
	hm.CipherSuite, err = ParseCipherSuites(buf[wi : wi+(int(hm.CipherSuiteLen))])
	if err != nil {
		return nil, err
	}
	wi += int(hm.CipherSuiteLen)

	// CompressionMethods:
	if len(buf[wi:]) < len(hm.CompressionMethods[:]) {
		return nil, errors.New("client hello message has invalid format")
	}
	wi += copy(hm.CompressionMethods[:], buf[wi:])

	// Extensions:
	if len(buf[wi:]) < int(ExtensionsLengthByteSize) {
		return nil, errors.New("client hello message has invalid format")
	}
	hm.ExtensionsLen = (uint16(buf[wi]) << 8) + uint16(buf[wi+1])
	wi += int(ExtensionsLengthByteSize)
	if len(buf[wi:]) < int(hm.ExtensionsLen) {
		return nil, errors.New("client hello message has invalid cipher suite length")
	}
	hm.ExtensionData = make([]byte, hm.ExtensionsLen)
	wi += copy(hm.ExtensionData[:], buf[wi:])

	// Final sanity check:
	common.AssertImpl(wi-int(HandshakeHeaderByteSize) == int(hm.Length))

	return hm, nil
}

func (hm *ClientHelloMsg) ToBinary() []byte {
	common.AssertImpl(hm != nil)
	// pre-allocate if length is known, else cap is HandshakeHeaderByteSize
	raw := make([]byte, 0, hm.Length+uint(HandshakeHeaderByteSize))

	raw = append(raw, byte(hm.Type))
	raw = append(raw, byte(hm.Length>>16), byte(hm.Length>>8), byte(hm.Length))
	raw = append(raw, hm.TLSVersion[:]...)
	raw = append(raw, hm.Random[:]...)
	raw = append(raw, hm.SessionIDLen)
	raw = append(raw, hm.SessionID[:]...)
	raw = append(raw, byte(hm.CipherSuiteLen>>8), byte(hm.CipherSuiteLen))
	for i := 0; i < len(hm.CipherSuite); i++ {
		cs := hm.CipherSuite[i]
		raw = append(raw, byte(cs>>8), byte(cs))
	}
	raw = append(raw, hm.CompressionMethods[:]...)
	raw = append(raw, byte(hm.ExtensionsLen>>8), byte(hm.ExtensionsLen))
	raw = append(raw, hm.ExtensionData[:]...)

	if hm.Length == 0 {
		// Automatically figure out the length.
		// Length was previously written as 0, now it's calculated and we need to update it.
		hm.Length = uint(len(raw)) - uint(HandshakeHeaderByteSize)
		raw[1] = byte(hm.Length >> 16)
		raw[2] = byte(hm.Length >> 8)
		raw[3] = byte(hm.Length)
	} else {
		// If length is set it should be correct!
		common.AssertImpl(hm.Length == uint(len(raw))-uint(HandshakeHeaderByteSize))
	}

	return raw
}
