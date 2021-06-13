package internal

import (
	"fmt"
	"net"
	"time"

	limitconn "github.com/tls-handshake/pkg/limit_conn"
)

var (
	preHandshakeConnLimit = time.Second * 2
)

type Server struct {}

func (s *Server) Listen(address string) error {
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}

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
	lconn := limitconn.Wrap(conn)
	// fast close of connections before the handshake, because we do not know the request origin and it might be a DDOS.
	lconn.SetLimit(preHandshakeConnLimit)
	hs := NewServerHandshake(lconn)
	if err := hs.Handshake(); err != nil {
		fmt.Println(err)
		lconn.Close()
		return
	}
}
