package main

import (
	"github.com/tls-handshake/internal"
)

const (
	address = "127.0.0.2:8082"
)

func main() {
	var srv internal.Server
	if err := srv.Listen(address); err != nil {
		panic(err)
	}
}
