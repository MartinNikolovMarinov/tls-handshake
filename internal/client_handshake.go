package internal

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/pkg/streams"
)

var (
	ImplementationErr = errors.New("internal error") // should never happen, usually causes a panic
)

type clientHandshake struct {
	rawConn net.Conn
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
	cfg := &tlstypes.ClientHelloExtParams{
		KeyShareExtParams: &tlstypes.KeyShareExtParams{
			CurveID: tls.CurveP256, // default curve
			PubKey:  []byte("1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"), // FIXME: start here, generete public key!
		},
	}
	r := tlstypes.MakeClientHelloRecord(cfg)
	rBytes := r.ToBinary()
	if err := streams.WriteAllBytes(c.rawConn, rBytes); err != nil {
		return err
	}
	return nil
}

func (c *clientHandshake) readServerHelloMsg() error {
	var buf [tlstypes.MaxSizeOfPlaintextRecord]byte
	n, err := c.rawConn.Read(buf[:])
	if err != nil {
		return err
	}

	record, err := tlstypes.ParseRecord(buf[:n])
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
		hm, err := tlstypes.ParseServerHelloMsg(record.Data)
		if err != nil {
			return err
		}
		// TODO: save hm
		_ = hm
	default:
		err = fmt.Errorf("received unsupported record type %d", record.RecordType)
	}

	return nil
}
