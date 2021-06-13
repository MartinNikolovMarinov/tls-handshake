package tlstypes

type HandshakeMsgType uint8

const (
	ClientHelloMsgType HandshakeMsgType = 0x1
	ServerHelloMsgType HandshakeMsgType = 0x2
)
