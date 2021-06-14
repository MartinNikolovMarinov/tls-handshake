package internal

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/internal/ecdh"
	"github.com/tls-handshake/internal/suite"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/internal/tls_types/extensions"
	limitconn "github.com/tls-handshake/pkg/limit_conn"
	"github.com/tls-handshake/pkg/streams"
)

type serverHandshake struct {
	rawConn     *limitconn.Wrapper
	clientHello *tlstypes.ClientHelloMsg
	serverHello *tlstypes.ServerHelloMsg
	seq         uint64

	serverPrivateKey  *ecdsa.PrivateKey
	clientPubKeyBytes []byte
	clientPubicKey    *ecdsa.PublicKey
	clientHandshakeKey []byte
	serverHandshakeKey []byte
	clientHandshakeIv []byte
	serverHandshakeIv []byte
}

func NewServerHandshake(conn *limitconn.Wrapper) *serverHandshake {
	ret := &serverHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *serverHandshake) Handshake() error {
	if err := c.readClientHelloMsg(); err != nil {
		c.sendFatalAlert()
		return err
	}
	cfg := &tlstypes.ServerHelloExtParams{}
	if err := c.genServerKey(cfg); err != nil {
		c.sendFatalAlert()
		return err
	}
	if err := c.writeServerHelloMsg(cfg); err != nil {
		c.sendFatalAlert()
		return err
	}

	sharedKey, err := ecdh.GenerateSharedSecret(c.serverPrivateKey, c.clientPubicKey)
	if err != nil {
		c.sendFatalAlert()
		return err
	}

	helloHash, err := c.calculateHandshakeHash()
	if err != nil {
		c.sendFatalAlert()
		return err
	}

	c.seq = 0 // start counting records received

	earlySecret := suite.Extract(nil, nil)
	derivedSecret := suite.DeriveSecret(earlySecret, "derived", nil)
	handshakeSecret := suite.Extract(sharedKey, derivedSecret)
	clientHandshakeTrafficSecret := suite.DeriveSecret(handshakeSecret, suite.ClientHandshakeTrafficLabel, helloHash)
	serverHandshakeTrafficSecret := suite.DeriveSecret(handshakeSecret, suite.ServerHandshakeTrafficLabel, helloHash)
	c.clientHandshakeKey = suite.DeriveSecret(clientHandshakeTrafficSecret, suite.KeyLabel, nil)
	c.serverHandshakeKey = suite.DeriveSecret(serverHandshakeTrafficSecret, suite.KeyLabel, nil)
	c.clientHandshakeIv = suite.DeriveSecret(clientHandshakeTrafficSecret, suite.IVLabel, nil)
	c.serverHandshakeIv = suite.DeriveSecret(serverHandshakeTrafficSecret, suite.IVLabel, nil)

	fmt.Println("hadshake success")
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
	c.clientPubKeyBytes = kse.PublicKey
	c.clientHello = clientHelloMsg
	c.clientPubicKey, err = ecdh.UnmarshalPubKey(ecdh.DefaultCurve, kse.PublicKey)
	if err != nil {
		return err
	}

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

// TODO: code dup:
func (c *serverHandshake) genServerKey(cfg *tlstypes.ServerHelloExtParams) error {
	common.AssertImpl(cfg != nil)
	priv, pub, err := ecdh.GenerateKey(ecdh.DefaultCurve, crand.Reader)
	if err != nil {
		return err
	}
	pubBytes := ecdh.MarshalPubKey(pub)
	cfg.KeyShareExtParams = &tlstypes.KeyShareExtParams{
		CurveID: ecdh.DefaultCurveID,
		PubKey:  pubBytes,
	}

	// save state:
	c.serverPrivateKey = priv

	return nil
}

// TODO: code dup:
func (c *serverHandshake) calculateHandshakeHash() (h hash.Hash, err error) {
	h = sha256.New()
	_, err = h.Write(c.clientHello.ToBinary())
	if err != nil {
		return nil, err
	}
	_, err = h.Write(c.serverHello.ToBinary())
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (c *serverHandshake) sendFatalAlert() {
	a := &tlstypes.Alert{
		Level:       tlstypes.FatalAlertLevel,
		Description: tlstypes.HandshakeFailure,
	}
	r := tlstypes.MakeAlertRecord(a)
	_, _ = r.WriteTo(c.rawConn)
}
