package server

type ServerHandshake interface {
	Handshake() error
}