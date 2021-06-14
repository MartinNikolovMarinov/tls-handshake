package main

import (
	"fmt"
	"os"
	"time"

	"github.com/tls-handshake/internal"
)

const (
	address = "127.0.0.2"
	port    = 8082
)

func main() {
	var client internal.Client
	if err := client.Connect(address, port); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for i := 0; i < 10; i++ {
		if err := client.Ping(); err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		time.Sleep(time.Second)
	}

	client.Disconnect()
}
