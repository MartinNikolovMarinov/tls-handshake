package main

import (
	"fmt"
	"os"
	"time"

	"github.com/tls-handshake/internal"
)

const (
	address = "127.0.0.2"
	port    = 8081
)

func main() {
	var client internal.Client
	if err := client.Connect(address, port); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	if err := client.Ping(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	time.Sleep(time.Second)
	if err := client.Ping(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	client.Disconnect()
}
