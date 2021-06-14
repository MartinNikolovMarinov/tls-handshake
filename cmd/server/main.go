package main

import (
	"fmt"
	"os"

	"github.com/tls-handshake/internal"
)

const (
	address = "127.0.0.2"
	port    = 8082
)

func main() {
	var srv internal.Server
	if err := srv.Listen(address, port); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
