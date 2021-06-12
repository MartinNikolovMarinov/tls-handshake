package client

type ClientHandshake interface {
	Handshake() error
}