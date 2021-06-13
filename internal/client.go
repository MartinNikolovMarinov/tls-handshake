package internal

import (
	"errors"
	"fmt"
	"net"

	tlstypes "github.com/tls-handshake/internal/tls_types"
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
	// var buf bytes.Buffer
	// record := tlstypes.MarshalRecordHeader(&tlstypes.Record{
	// 	RecordType:      tlstypes.HandshakeRecord,
	// 	TLSVersion:      tls.VersionTLS13,
	// 	Length: 0xca, // TODO: write correct value here !
	// })
	// buf.Write(record)

	// // handShakeHeader := tlstypes.MarshalHandshakeHeader(&tlstypes.HandshakeHeader{
	// // 	DataLen:              198, // TODO: calculate actual !
	// // 	HandshakeMessageType: tlstypes.ClientHelloMsgType,
	// // })
	// // buf.Write(handShakeHeader)

	// b := buf.Bytes()
	// n, err := c.rawConn.Write(b)
	// if err != nil {
	// 	return err
	// }
	// if n != buf.Len() {
	// 	// NOTE: can implement retry policy here.
	// 	return errors.New("short write - failed to write client hello")
	// }

	return nil
}

func (c *clientHandshake) readServerHelloMsg() error {
	someData := make([]byte, 1000)
	n, err := c.rawConn.Read(someData)
	if err != nil {
		return err
	}
	if n == 2 {
		// maybe received an alert
		alert, err := tlstypes.ParseAlert(someData[0:n])
		if err == nil {
			return fmt.Errorf("received alert message %+v", alert)
		}
	}

	return nil
}
