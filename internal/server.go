package internal

import (
	"fmt"
	"net"
	"time"

	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/rand"
)

var (
	preHandshakeConnLimit = time.Second * 2
)

type Server struct{}

func (s *Server) Listen(ipv4 string, port uint16) error {
	address := fmt.Sprintf("%s:%d", ipv4, port)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

	fmt.Printf("server listening on %d", port)
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

func (s *Server) handleConnection(conn net.Conn) {
	lconn := limitconn.Wrap(conn, "server_"+rand.GenString(32))
	// fast close of connections before the handshake, because we do not know the request origin and it might be a DDOS.
	lconn.SetLimit(preHandshakeConnLimit)
	hs := NewServerHandshake(lconn)
	if err := hs.Handshake(); err != nil {
		fmt.Println(err)
		lconn.Close()
		return
	}
}
