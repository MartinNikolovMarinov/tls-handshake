package main

import (
	_ "github.com/tls-handshake/internal/ecdh_crypto"
	_ "github.com/tls-handshake/internal/tls_types"
)

func main() {
	// _ = ecdhcrypto.NewECDHCrypto(elliptic.P256(), rand.Reader)

	// conn, err := net.Dial("tcp", "127.0.0.2:8082")
	// if err != nil {
	// 	panic(err)
	// }
}
