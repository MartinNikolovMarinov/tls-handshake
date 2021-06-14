package internal

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/tls-handshake/internal/suite"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	cbytes "github.com/tls-handshake/pkg/bytes"
	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/rand"
)

const (
	clientHandshakeLimit = time.Minute
)

type Client struct {
	rawConn *limitconn.Wrapper
	handshake *clientHandshake
}

func (c *Client) Connect(ipv4 string, port uint16) error {
	addrss := fmt.Sprintf("%s:%d", ipv4, port)
	conn, err := net.Dial("tcp", addrss)
	if err != nil {
		return err
	}

	fmt.Printf("client connection on %d\n", port)
	c.rawConn = limitconn.Wrap(conn, "client_"+rand.GenString(32))
	c.rawConn.SetLimit(clientHandshakeLimit)
	c.handshake = NewClientHandshake(c.rawConn)
	if err := c.handshake.Handshake(); err != nil {
		c.rawConn.Close()
		return err
	}

	return nil
}

func (s *Client) Ping() error {
	plaintext := []byte("PING")
	nonce := cbytes.UInt64ToBytes(s.handshake.seq)
	ciphertext, err := suite.Encrypt(plaintext, s.handshake.serverHandshakeKey, nonce)
	if err != nil {
		return err
	}
	ciphertext, err = suite.Encrypt(ciphertext, cbytes.Xor(s.handshake.serverHandshakeIv, nonce), nonce)
	if err != nil {
		return err
	}
	_, err = s.rawConn.Write(ciphertext)
	if err != nil {
		return err
	}

	s.handshake.seq++
	return nil
}


func (c *Client) recv() error {
	var data [tlstypes.MaxSizeOfPlaintextRecord]byte
	n, err := c.rawConn.Read(data[:])
	if err != nil {
		return err
	}

	ciphertext := data[:n]
	nonce := cbytes.UInt64ToBytes(c.handshake.seq)
	ciphertext, err = suite.Decrypt(ciphertext, cbytes.Xor(c.handshake.serverHandshakeIv, nonce), nonce)
	if err != nil {
		return err
	}
	plaintext, err := suite.Decrypt(ciphertext, c.handshake.serverHandshakeKey, nonce)
	if err != nil {
		return err
	}

	switch {
	case bytes.Equal(plaintext, []byte("PONG")):
		fmt.Println(string(plaintext))
	default:
		return errors.New("unsupported response message")
	}

	c.handshake.seq++
	return nil
}

func (c *Client) Disconnect() {
	_ = c.rawConn.Close()
}
