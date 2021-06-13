package internal

type Handshaker interface {
	Handshake() error
}