package internal

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/tls-handshake/internal/suite"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	cbytes "github.com/tls-handshake/pkg/bytes"
	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/rand"
)

var (
	preHandshakeConnLimit = time.Second * 2
	postHandshakeConnLimit = time.Minute
	// postHandshakeConnLimit = time.Second * 3 // TODO: temporary short interval for debugging
)

type Server struct {
	connections   []connState
	connsMux      sync.Mutex
	connIdCounter uint32
}

func (s *Server) Listen(ipv4 string, port uint16) error {
	s.connections = make([]connState, 0)
	address := fmt.Sprintf("%s:%d", ipv4, port)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	fmt.Printf("server listening on %d\n", port)
	quit := make(chan struct{}, 0)
	defer close(quit)
	s.startSentinel(quit)
	for {
		conn, err := listen.Accept()
		if err != nil {
			fmt.Println(err)
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) startSentinel(quit <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for {
		select {
			case <- ticker.C:
				s.cleanConnections()
			case <- quit:
				fmt.Println("sentinel stopping")
				ticker.Stop()
				return
			}
		}
	}()
}

func (s *Server) cleanConnections() {
	s.connsMux.Lock()
	defer s.connsMux.Lock()

	updated := make([]connState, 0, len(s.connections))
	for i := 0; i < len(s.connections); i++ {
		c := s.connections[i]
		if c.rawConn != nil && !c.rawConn.IsConnClosed() {
			updated = append(updated, s.connections[i])
		}
	}

	s.connections = updated
	fmt.Println(len(s.connections), "still active")
}

func (s *Server) handleConnection(conn net.Conn) {
	var err error
	rawConn := limitconn.Wrap(conn, "server_"+rand.GenString(32))
	rawConn.SetLimit(preHandshakeConnLimit)
	handshake := NewServerHandshake(rawConn)
	if err = handshake.Handshake(); err != nil {
		fmt.Println(err)
		rawConn.Close()
		return
	}

	rawConn.SetLimit(postHandshakeConnLimit)

	state := connState{rawConn, handshake}

	s.connsMux.Lock()
	s.connIdCounter++
	s.connections = append(s.connections, state)
	s.connsMux.Unlock()

	for {
		err = state.recv()
		if err == io.EOF {
			err = nil // EOF is expected when communication is done.
			break
		}
		if err != nil {
			break
		}
		if err = state.Pong(); err != nil {
			break
		}
	}

	if err != nil {
		fmt.Println(err)
	}

	rawConn.Close()
}

type connState struct {
	rawConn   *limitconn.Wrapper
	handshake *serverHandshake
}

func (s *connState) Pong() error {
	plaintext := []byte("PONG")
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

func (c *connState) recv() error {
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
	case bytes.Equal(plaintext, []byte("PING")):
		fmt.Println(string(plaintext))
	default:
		return errors.New("unsupported response message")
	}

	c.handshake.seq++
	return nil
}
