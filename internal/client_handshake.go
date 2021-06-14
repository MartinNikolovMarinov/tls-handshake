package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	crand "crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"net"

	"github.com/tls-handshake/internal/common"
	"github.com/tls-handshake/internal/ecdh"
	"github.com/tls-handshake/internal/suite"
	tlstypes "github.com/tls-handshake/internal/tls_types"
	"github.com/tls-handshake/internal/tls_types/extensions"
	"github.com/tls-handshake/pkg/bytes"
	"github.com/tls-handshake/pkg/streams"
)

type clientHandshake struct {
	rawConn     net.Conn
	clientHello *tlstypes.ClientHelloMsg
	serverHello *tlstypes.ServerHelloMsg
	seq         uint64

	clientPrivateKey  *ecdsa.PrivateKey
	serverPubKeyBytes []byte
	serverPubicKey    *ecdsa.PublicKey
}

func NewClientHandshake(conn net.Conn) Handshaker {
	ret := &clientHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *clientHandshake) Handshake() error {
	cfg := &tlstypes.ClientHelloExtParams{}
	if err := c.genClientKey(cfg); err != nil {
		return err
	}
	if err := c.writeClientHelloMsg(cfg); err != nil {
		return err
	}
	if err := c.readServerHelloMsg(); err != nil {
		return err
	}

	sharedKey, err := ecdh.GenerateSharedSecret(c.clientPrivateKey, c.serverPubicKey)
	if err != nil {
		return err
	}

	helloHash, err := c.calculateHandshakeHash()
	if err != nil {
		return err
	}

	// NOTE: we can consider the handshake a success from here

	c.seq = 0 // start counting records receive

	earlySecret := suite.Extract(nil, nil)
	derivedSecret := suite.DeriveSecret(earlySecret, "derived", nil)
	handshakeSecret := suite.Extract(sharedKey, derivedSecret)
	clientHandshakeTrafficSecret := suite.DeriveSecret(handshakeSecret, suite.ClientHandshakeTrafficLabel, helloHash)
	serverHandshakeTrafficSecret := suite.DeriveSecret(handshakeSecret, suite.ServerHandshakeTrafficLabel, helloHash)
	clientHandshakeKey := suite.DeriveSecret(clientHandshakeTrafficSecret, suite.KeyLabel, nil)
	serverHandshakeKey := suite.DeriveSecret(serverHandshakeTrafficSecret, suite.KeyLabel, nil)
	clientHandshakeIv := suite.DeriveSecret(clientHandshakeTrafficSecret, suite.IVLabel, nil)
	serverHandshakeIv := suite.DeriveSecret(serverHandshakeTrafficSecret, suite.IVLabel, nil)

	_ = clientHandshakeKey
	_ = clientHandshakeIv

	var bbb [1000]byte
	n, err := c.rawConn.Read(bbb[:])
	if err != nil {
		panic("err")
	}

	ciphertext := bbb[:n]

	nonce := bytes.Int64ToBytes(c.seq)

	a, err := aes.NewCipher(bytes.Xor(serverHandshakeIv, nonce))
	if err != nil {
		panic(err)
	}
	aesgcm, err := cipher.NewGCM(a)
	if err != nil {
		panic(err)
	}

	nonce = bytes.PadSlice(nonce, 0x0, aesgcm.NonceSize())

	ciphertext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	a, err = aes.NewCipher(serverHandshakeKey)
	if err != nil {
		panic(err)
	}
	aesgcm, err = cipher.NewGCM(a)
	if err != nil {
		panic(err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	fmt.Println(plaintext)

	return nil
}

func (c *clientHandshake) writeClientHelloMsg(cfg *tlstypes.ClientHelloExtParams) error {
	common.AssertImpl(cfg != nil)

	clientHelloMsg := tlstypes.MakeClientHelloMessage(cfg)
	r := tlstypes.MakeClientHelloRecord(clientHelloMsg)
	rBytes := r.ToBinary()
	if err := streams.WriteAllBytes(c.rawConn, rBytes); err != nil {
		return err
	}

	// save state:
	c.clientHello = clientHelloMsg

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

	var serverHelloMsg *tlstypes.ServerHelloMsg

	switch record.RecordType {
	case tlstypes.AlertRecord:
		alert, err := tlstypes.ParseAlert(record.Data)
		if err == nil {
			return fmt.Errorf("received alert message %+v", alert)
		}
		return errors.New("failed to parse alert record")
	case tlstypes.HandshakeRecord:
		serverHelloMsg, err = tlstypes.ParseServerHelloMsg(record.Data)
		if err != nil {
			return err
		}
	default:
		err = fmt.Errorf("received unsupported record type %d", record.RecordType)
	}

	exts, err := extensions.ParseExtensions(serverHelloMsg.ExtensionData, serverHelloMsg.ExtensionsLen)
	if err != nil {
		return err
	}
	ext := extensions.FindExtension(exts, extensions.KeyShareType)
	kse, ok := ext.(*extensions.KeyShareExtension)
	common.AssertImpl(ok)

	// save state:
	c.serverHello = serverHelloMsg
	c.serverPubKeyBytes = kse.PublicKey
	c.serverPubicKey, err = ecdh.UnmarshalPubKey(ecdh.DefaultCurve, kse.PublicKey)
	if err != nil {
		return err
	}

	return nil
}

// TODO: code dup:
func (c *clientHandshake) genClientKey(cfg *tlstypes.ClientHelloExtParams) error {
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
	c.clientPrivateKey = priv

	return nil
}

// TODO: code dup
func (c *clientHandshake) calculateHandshakeHash() (h hash.Hash, err error) {
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
