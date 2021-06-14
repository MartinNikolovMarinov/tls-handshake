package internal

import (
	crand "crypto/rand"
	"errors"
	"fmt"
	"net"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/internal/ecdh"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/pkg/streams"
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
	cfg := &tlstypes.ClientHelloExtParams{}
	if err := c.generateKey(cfg); err != nil {
		return err
	}
	if err := c.writeClientHelloMsg(cfg); err != nil {
		return err
	}
	if err := c.readServerHelloMsg(); err != nil {
		return err
	}

	return nil
}

func (c *clientHandshake) generateKey(cfg * tlstypes.ClientHelloExtParams) error {
	common.AssertImpl(cfg != nil)
	mgr := ecdh.NewManager(ecdh.DefaultCurve, crand.Reader)
	_, pub, err := mgr.GenerateKey()
	if err != nil {
		return err
	}
	pubBytes, err := mgr.MarshalPubKey(pub)
	if err != nil {
		return err
	}
	cfg.KeyShareExtParams = &tlstypes.KeyShareExtParams{
		CurveID: ecdh.DefaultCurveID,
		PubKey: pubBytes,
	}

	return nil
}

func (c *clientHandshake) writeClientHelloMsg(cfg * tlstypes.ClientHelloExtParams) error {
	common.AssertImpl(cfg != nil)

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
