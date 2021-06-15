package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/tls-handshake/internal"
)

func main() {
	port := flag.Int("p", 8081, "Port to listen on (optional)")
	address := flag.String("ip", "127.0.0.2", "IP address to use (optional)")
	flag.Parse()

	if port == nil || address == nil {
		fmt.Println("invalid command line arguments provided")
		os.Exit(1)
	}

	var srv internal.Server
	if err := srv.Listen(*address, uint16(*port)); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
