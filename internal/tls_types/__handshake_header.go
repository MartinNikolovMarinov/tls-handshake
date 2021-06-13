package tlstypes

import "errors"

type HandshakeMsgType uint8

const (
	ClientHelloMsgType HandshakeMsgType = 1
)

type HandshakeHeader struct {
	HandshakeMessageType HandshakeMsgType
	DataLen              uint
}

func ParseHandshakeHeader(raw []byte) (HandshakeHeader, error) {
	var ret HandshakeHeader
	if len(raw) != int(HandshakeHeaderByteSize) {
		return ret, errors.New("invalid handshake header byte size")
	}

	switch HandshakeMsgType(raw[0]) {
	case ClientHelloMsgType:
		ret.HandshakeMessageType = ClientHelloMsgType
	default:
		return ret, errors.New("unsupported handshake message type")
	}

	ret.DataLen = (uint(raw[1]) << 16) + (uint(raw[2]) << 8) + uint(raw[3])
	return ret, nil
}
