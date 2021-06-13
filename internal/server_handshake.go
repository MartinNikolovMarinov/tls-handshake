package internal

import (
	"errors"
	"fmt"

	tlstypes "github.com/tls-handshake/internal/tls_types"
	limitconn "github.com/tls-handshake/pkg/limit_conn"
)
type serverHandshake struct {
	rawConn *limitconn.Wrapper
}

func NewServerHandshake(conn *limitconn.Wrapper) Handshaker {
	ret := &serverHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *serverHandshake) Handshake() error {
	if err := c.readClientHelloMsg(); err != nil {
		// try to send a fatal alert:
		a := &tlstypes.Alert{
			Level:       tlstypes.FatalAlertLevel,
			Description: tlstypes.HandshakeFailure,
		}
		r := tlstypes.MakeAlertRecord(a)
		_, _ = r.WriteTo(c.rawConn)
		return err
	}

	fmt.Println("success")
	c.rawConn.Close()
	return errors.New("TMP boom")
}

func (c *serverHandshake) readClientHelloMsg() error {
	var buf [tlstypes.MaxSizeOfPlaintextRecord]byte
	n, err := c.rawConn.Read(buf[:])
	if err != nil {
		return err
	}

	record, err := tlstypes.ParseRecord(buf[:n])
	if err != nil {
		return err
	}
	if record.RecordType != tlstypes.HandshakeRecord {
		return errors.New("not a handshake record")
	}

	hm, err := tlstypes.ParseClientHelloMsg(record.Data)
	if err != nil {
		return err
	}
	_ = hm

	return nil
}