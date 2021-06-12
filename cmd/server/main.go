package main

import (
	"fmt"
	"net"

	"github.com/tls-handshake/internal/server"
)

const (
	address = "127.0.0.2:8082"
)

func handleConnection(conn net.Conn) {
	hs := server.NewServerHandshake(conn)
	if err := hs.Handshake(); err != nil {
		fmt.Println(err) // TODO: alert for errors
		return
	}
}

func main() {
	listen, err := net.Listen("tcp", address)
	if err != nil {
		panic(err)
	}

	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(err)
			continue
		}

		go handleConnection(conn)
	}
}
