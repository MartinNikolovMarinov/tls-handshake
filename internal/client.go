package internal

import (
	"fmt"
	"net"

	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/rand"
)

type Client struct {
	rawConn *limitconn.Wrapper
}

func (o *Client) Connect(ipv4 string, port uint16) error {
	addrss := fmt.Sprintf("%s:%d", ipv4, port)
	conn, err := net.Dial("tcp", addrss)
	if err != nil {
		return err
	}

	fmt.Printf("client connection on %d\n", port)
	o.rawConn = limitconn.Wrap(conn, "client_"+rand.GenString(32))
	hs := NewClientHandshake(o.rawConn)
	if err := hs.Handshake(); err != nil {
		o.rawConn.Close()
		return err
	}

	return nil
}

func (o *Client) Disconnect() {
	_ = o.rawConn.Close()
}
