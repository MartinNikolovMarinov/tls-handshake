package server

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/tls-handshake/internal/common"
	tcpconn "github.com/tls-handshake/internal/tcp_conn"
	tlstypes "github.com/tls-handshake/internal/tls_types"
)
type serverHandshake struct {
	rawConn net.Conn // raw TCP connection

	random     []byte
	suites     []tlstypes.CipherSuite
	tlsVersion uint16
}

func NewServerHandshake(conn net.Conn) ServerHandshake {
	ret := &serverHandshake{
		rawConn: conn,
	}
	return ret
}

func (c *serverHandshake) Handshake() error {
	if err := c.readClientHelloMsg(); err != nil {
		tcpconn.CloseConnAggressively(c.rawConn, []byte("handshake failed"), time.Second)
		return err
	}

	return nil
}

func (c *serverHandshake) readClientHelloMsg() error {
	var buf [common.MAX_SIZE_OF_TCP_PACKET]byte
	ri := 0 // read index

	recordHeader, n, err := c.readRecordHeader(buf[ri:])
	if err != nil {
		return err
	}
	if recordHeader.RecordType != tlstypes.HandshakeRecord {
		return errors.New("not a handshake record")
	}
	ri += n

	handShakeHeader, n, err := c.readHandshakeHeader(buf[ri:])
	if err != nil {
		return err
	}
	if handShakeHeader.HandshakeMessageType != tlstypes.ClientHelloMsgType {
		return errors.New("expected a client hello message")
	}
	ri += n

	// NOTE: version is hardcoded to 1.2 and should be ignored
	if err = c.readAhead(buf[ri:], int(tlstypes.VersionByteSize)); err != nil {
		return err
	}
	ri += int(tlstypes.VersionByteSize)

	if c.random, err = c.readBytes(buf[ri:], int(tlstypes.RandomByteSize)); err != nil {
		return err
	}
	ri += int(tlstypes.RandomByteSize)

	_, n, err = c.readSessionID(buf[ri:])
	if err != nil {
		return err
	}
	ri += n

	c.suites, n, err = c.readCipherSuites(buf[ri:])
	if err != nil {
		return err
	}
	ri += n

	// NOTE: compression is not allowed in TLS 1.3, so ignore this too
	if err = c.readAhead(buf[ri:], int(tlstypes.CompressionMethodsByteSize)); err != nil {
		return err
	}
	ri += int(tlstypes.CompressionMethodsByteSize)

	// TODO: Extensions are ignored for now. Might need Extension - Server Name for http proxy server to work
	if err = c.readAhead(buf[ri:], int(tlstypes.ExtensionsLengthByteSize)); err != nil {
		return err
	}
	ri += int(tlstypes.ExtensionsLengthByteSize)

	rest := int(recordHeader.BytesInHandsake) - ri
	if rest < 0 {
		return errors.New("invalid client hello message size")
	}
	if err = c.readAhead(buf[ri:], rest); err != nil {
		return err
	}

	return nil
}

func (c *serverHandshake) readRecordHeader(buf []byte) (ret tlstypes.RecordHeader, bytesRead int, err error) {
	hsParamsSanityCheck(buf, int(tlstypes.RecordHeaderByteSize))
	var n int
	recordHeaderBuf := buf[0:tlstypes.RecordHeaderByteSize]
	if n, err = c.rawConn.Read(recordHeaderBuf); err != nil {
		return ret, 0, err
	}
	if n != int(tlstypes.RecordHeaderByteSize) {
		return ret, 0, errors.New("invalid record header bytes size")
	}
	if ret, err = tlstypes.ParseRecordHeader(recordHeaderBuf); err != nil {
		return ret, 0, err
	}
	return ret, n, nil
}

func (c *serverHandshake) readHandshakeHeader(buf []byte) (ret tlstypes.HandshakeHeader, bytesRead int, err error) {
	hsParamsSanityCheck(buf, int(tlstypes.HandshakeHeaderByteSize))
	var n int
	hsHeaderBuf := buf[0:tlstypes.HandshakeHeaderByteSize]
	if n, err = c.rawConn.Read(hsHeaderBuf); err != nil {
		return ret, 0, err
	}
	if n != int(tlstypes.HandshakeHeaderByteSize) {
		return ret, 0, errors.New("invalid handshake header bytes size")
	}
	if ret, err = tlstypes.ParseHandshakeHeader(hsHeaderBuf); err != nil {
		return ret, 0, err
	}
	return ret, n, nil
}

func (c *serverHandshake) readSessionID(buf []byte) (ret []byte, bytesRead int, err error) {
	n, err := c.rawConn.Read(buf[0:1])
	if err != nil {
		return nil, 0, err
	}
	if n != 1 {
		return nil, n, errors.New("failed to read session id")
	}

	sessionIdBytesSize := uint8(buf[0])
	sessionId, err := c.readBytes(buf[1:], int(sessionIdBytesSize))
	if err != nil {
		return nil, n, err
	}

	return sessionId, len(sessionId) + n, nil
}

func (c *serverHandshake) readCipherSuites(buf []byte) (ret []tlstypes.CipherSuite, bytesRead int, err error) {
	suiteLenBytes, err := c.readBytes(buf, 2)
	if err != nil {
		return nil, 0, errors.New("invalid cipher suites byte size")
	}

	suiteLen := (int(suiteLenBytes[0]) << 8) + int(suiteLenBytes[1])
	if suiteLen <= 0 {
		return nil, 0, errors.New("invalid cipher suites byte size")
	}

	cipherBytes, err := c.readBytes(buf[2:], suiteLen)
	if err != nil {
		return nil, 0, errors.New("invalid cipher suites")
	}

	ret, err = tlstypes.ParseCipherSuites(cipherBytes[:suiteLen])
	if err != nil {
		return nil, 0, err
	}

	bytesRead += len(suiteLenBytes)
	bytesRead += suiteLen

	return ret, bytesRead, nil
}

func (c *serverHandshake) readBytes(buf []byte, bytesToRead int) ([]byte, error) {
	bufPtr := buf[:bytesToRead]
	n, err := c.rawConn.Read(bufPtr)
	if err != nil {
		return nil, err
	}
	if n != bytesToRead {
		return nil, fmt.Errorf("short read - tried to read %d bytes, but read only %d", bytesToRead, n)
	}

	retCopy := make([]byte, len(bufPtr))
	copy(retCopy, bufPtr)
	return retCopy, nil
}

func (c *serverHandshake) readAhead(buf []byte, bytesToRead int) error {
	hsParamsSanityCheck(buf, bytesToRead)
	ignoreBuf := buf[0:bytesToRead]
	n, err := c.rawConn.Read(ignoreBuf)
	if err != nil {
		return err
	}
	if n != bytesToRead {
		return fmt.Errorf("short read - tried to read %d bytes, but read only %d", bytesToRead, n)
	}
	return nil
}

func hsParamsSanityCheck(buf []byte, minBufSize int) {
	if len(buf) < minBufSize {
		panic(common.ImplementationErr)
	}
}