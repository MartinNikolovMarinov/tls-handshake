package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/tls-handshake/internal"
)

func main() {
	port := flag.Int("p", 8081, "Port to connect to (optional)")
	address := flag.String("ip", "127.0.0.2", "IP address to connect to (optional)")
	flag.Parse()

	if port == nil || address == nil {
		fmt.Println("invalid command line arguments provided")
		os.Exit(1)
	}

	var client internal.Client
	if err := client.Connect(*address, uint16(*port)); err != nil {
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
