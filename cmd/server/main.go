package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"time"

	ecdhcrypto "github.com/tls-handshake/internal/ecdh_crypto"
)

func main() {
    ec := ecdhcrypto.NewECDHCrypto()
    cfg := &ecdhcrypto.GenKeyConfig{
		Hosts:        "Test Company LLC.",
		Organization: []string{"Test Org"},
		ValidFrom:    time.Now(),
		ValidFor:     time.Hour * 720, // 30 days
		IsCA:         false,
		CurveType:    ecdhcrypto.Secp256r1,
	}
    pkbytes, certbytes, err := ec.GenerateSignedKey(cfg)
    if err != nil {
        panic(err)
    }

    cert, err := tls.X509KeyPair(certbytes, pkbytes)
    if err != nil {
        log.Fatalf("server: loadkeys: %s", err)
    }
    config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: false}
    config.Rand = rand.Reader
    service := "127.0.0.2:8001"
    listener, err := tls.Listen("tcp", service, &config)
    if err != nil {
        log.Fatalf("server: listen: %s", err)
    }
    log.Print("server: listening")

    counter := 0
    for {
        conn, err := listener.Accept()
        counter++
        fmt.Println(counter)
        if err != nil {
            log.Printf("server: accept: %s", err)
            break
        }
        defer conn.Close()
        log.Printf("server: accepted from %s", conn.RemoteAddr())
        tlscon, ok := conn.(*tls.Conn)
        if ok {
            log.Print("ok=true")
            state := tlscon.ConnectionState()
            for _, v := range state.PeerCertificates {
                log.Print(x509.MarshalPKIXPublicKey(v.PublicKey))
            }
        }
        go handleClient(conn)
    }
}

func handleClient(conn net.Conn) {
    defer conn.Close()
    buf := make([]byte, 512)
    for {
        log.Print("server: conn: waiting")
        n, err := conn.Read(buf)
        if err != nil {
            if err != nil {
                log.Printf("server: conn: read: %s", err)
            }
            break
        }
        log.Printf("server: conn: echo %q\n", string(buf[:n]))
        n, err = conn.Write(buf[:n])

        n, err = conn.Write(buf[:n])
        log.Printf("server: conn: wrote %d bytes", n)

        if err != nil {
            log.Printf("server: write: %s", err)
            break
        }
    }
    log.Println("server: conn: closed")
}