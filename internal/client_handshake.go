package internal

import (
	"errors"
	"fmt"
	"net"

	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/pkg/streams"
)

var (
	ImplementationErr = errors.New("internal error") // should never happen, usually cause a panic
)

type clientHandshake struct {
	rawConn net.Conn // raw TCP connection

	// random     []byte
	// suites     []tlstypes.CipherSuite
	// tlsVersion uint16
}

func NewClientHandshake(conn net.Conn) Handshaker {
	ret := &clientHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *clientHandshake) Handshake() error {
	if err := c.writeClientHelloMsg(); err != nil {
		return err
	}
	if err := c.readServerHelloMsg(); err != nil {
		return err
	}

	return nil
}

func (c *clientHandshake) writeClientHelloMsg() error {
	r := tlstypes.MakeClientHelloRecord()
	rBytes := r.ToBinary()
	if err := streams.WriteAllBytes(c.rawConn, rBytes); err != nil {
		return err
	}
	return nil
}

func (c *clientHandshake) readServerHelloMsg() error {
	someData := make([]byte, 1000)
	n, err := c.rawConn.Read(someData)
	if err != nil {
		return err
	}

	record, err := tlstypes.ParseRecord(someData[:n])
	if err != nil {
		return err
	}

	switch record.RecordType {
	case tlstypes.AlertRecord:
		alert, err := tlstypes.ParseAlert(record.Data)
		if err == nil {
			return fmt.Errorf("received alert message %+v", alert)
		}
		return errors.New("failed to parse alert record")
	case tlstypes.HandshakeRecord:
		// TODO: Parse server hello message here
	default:
		err = fmt.Errorf("received unsupported record type %d", record.RecordType)
	}

	return nil
}
