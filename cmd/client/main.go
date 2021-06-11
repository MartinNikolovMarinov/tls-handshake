package main

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	ecdhcrypto "github.com/tls-handshake/internal/ecdh_crypto"
	tlstypes "github.com/tls-handshake/internal/tls_types"
)

func main() {
	e := ecdhcrypto.NewECDHCrypto(elliptic.P256(), rand.Reader)
	priv, pub, err := e.GenerateKey()
	if err != nil {
		panic(err)
	}

	_ = priv
	_ = pub

	// con, err := net.Dial("tcp", "127.0.0.1:8081")
	// if err != nil {
	// 	panic(err)
	// }

	var (
		clientRandom [32]byte
		sessionId    [33]byte
	)
	_, _ = rand.Read(clientRandom[:])
	_, _ = rand.Read(sessionId[:])
	msg := tlstypes.ClientHelloRaw{
		RecordHeader:       [5]byte{0x16, 0x03, 0x04, 0x00, 0xca},
		HandshakeHeader:    [4]byte{0x01, 0x00, 0x00, 0xc6},
		ClientVersion:      [3]byte{0x03, 0x03},
		ClientRandom:       clientRandom,
		SessionID:          sessionId,
		CipherSuites:       [8]byte{0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03},
		CompressionMethods: [2]byte{0x01, 0x00},
		ExtensionsLength:   0x77,
	}

	var buf bytes.Buffer
	err = binary.Write(&buf, binary.LittleEndian, &msg)
	if err != nil {
		panic(err)
	}

	msg = tlstypes.ClientHelloRaw{}

	err = binary.Read(&buf, binary.LittleEndian, &msg)
	if err != nil {
		panic(err)
	}

	rec, err := tlstypes.ParseRecordHeader(msg.RecordHeader)
	if err != nil {
		panic(err)
	}
	fmt.Println(rec)

	hh, err := tlstypes.ParseHandshakeHeader(msg.HandshakeHeader)
	if err != nil {
		panic(err)
	}
	fmt.Println(hh)

	cs, err := tlstypes.ParseCipherSuites(msg.CipherSuites)
	if err != nil {
		panic(err)
	}
	fmt.Println(cs)
}

// FIXME: remove comments
// func main() {
//     ec := ecdhcrypto.NewECDHCrypto()
//     cfg := &ecdhcrypto.GenKeyConfig{
// 		Hosts:        "Test Company LLC.",
// 		Organization: []string{"Test Org"},
// 		ValidFrom:    time.Now(),
// 		ValidFor:     time.Hour * 720, // 30 days
// 		IsCA:         false,
// 		CurveType:    ecdhcrypto.Secp256r1,
// 	}
//     pkbytes, certbytes, err := ec.GenerateSignedKey(cfg)
//     if err != nil {
//         panic(err)
//     }

//     cert, err := tls.X509KeyPair(certbytes, pkbytes)
//     if err != nil {
//         log.Fatalf("client failed to load keys %s", err)
//     }
//     config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: true}
//     conn, err := tls.Dial("tcp", "127.0.0.2:8001", &config)
//     if err != nil {
//         log.Fatalf("client: dial: %s", err)
//     }
//     defer conn.Close()
//     log.Println("client: connected to: ", conn.RemoteAddr())

//     state := conn.ConnectionState()
//     for _, v := range state.PeerCertificates {
//         fmt.Println(x509.MarshalPKIXPublicKey(v.PublicKey))
//         fmt.Println(v.Subject)
//     }
//     log.Println("client: handshake: ", state.HandshakeComplete)
//     log.Println("client: mutual: ", state.NegotiatedProtocolIsMutual)

//     for i := 0; i < 5; i++ {
//         message := "Hello\n"
//         n, err := io.WriteString(conn, message)
//         if err != nil {
//             log.Fatalf("client: write: %s", err)
//         }
//         log.Printf("client: wrote %q (%d bytes)", message, n)

//         reply := make([]byte, 256)
//         n, err = conn.Read(reply)
//         log.Printf("client: read %q (%d bytes)", string(reply[:n]), n)
//         log.Print("client: exiting")
//         time.Sleep(time.Second * 5)
//     }
// }
