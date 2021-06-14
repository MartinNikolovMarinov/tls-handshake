package internal

import (
	crand "crypto/rand"
	"errors"
	"fmt"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/internal/ecdh"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/internal/tls_types/extensions"
	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/streams"
)

type serverHandshake struct {
	rawConn      *limitconn.Wrapper
	clientHello  *tlstypes.ClientHelloMsg
	serverHello  *tlstypes.ServerHelloMsg
	clientPubKey []byte
}

func NewServerHandshake(conn *limitconn.Wrapper) Handshaker {
	ret := &serverHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *serverHandshake) Handshake() error {
	if err := c.readClientHelloMsg(); err != nil {
		a := &tlstypes.Alert{
			Level:       tlstypes.FatalAlertLevel,
			Description: tlstypes.HandshakeFailure,
		}
		r := tlstypes.MakeAlertRecord(a)
		_, _ = r.WriteTo(c.rawConn)
		return err
	}

	cfg := &tlstypes.ServerHelloExtParams{}
	if err := c.genServerKey(cfg); err != nil {
		return err
	}

	if err := c.writeServerHelloMsg(cfg); err != nil {
		a := &tlstypes.Alert{
			Level:       tlstypes.FatalAlertLevel,
			Description: tlstypes.HandshakeFailure,
		}
		r := tlstypes.MakeAlertRecord(a)
		_, _ = r.WriteTo(c.rawConn)
		return err
	}

	fmt.Println("hadshake success")
	return nil
}

func (c *serverHandshake) genServerKey(cfg *tlstypes.ServerHelloExtParams) error {
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

	clientHelloMsg, err := tlstypes.ParseClientHelloMsg(record.Data)
	if err != nil {
		return err
	}

	exts, err := extensions.ParseExtensions(clientHelloMsg.ExtensionData, clientHelloMsg.ExtensionsLen)
	if err != nil {
		return err
	}
	ext := extensions.FindExtension(exts, extensions.KeyShareType)
	kse, ok := ext.(*extensions.KeyShareExtension)
	common.AssertImpl(ok)

	// save state
	c.clientPubKey = kse.PublicKey
	c.clientHello = clientHelloMsg

	return nil
}

func (c *serverHandshake) writeServerHelloMsg(cfg *tlstypes.ServerHelloExtParams) error {
	serverHelloMsg := tlstypes.MakeServerHelloMessage(cfg)
	r := tlstypes.MakeServerHelloRecord(serverHelloMsg)
	rBytes := r.ToBinary()
	if err := streams.WriteAllBytes(c.rawConn, rBytes); err != nil {
		return err
	}

	// save state
	c.serverHello = serverHelloMsg

	return nil
}
