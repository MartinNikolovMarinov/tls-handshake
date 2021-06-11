package tlstypes

// Client hello as defined here https://tls13.ulfheim.net/ and RFC 8446
type ClientHelloRaw struct {
	// TLS sessions are broken into the sending and receiving of "records", which are blocks of data with a type, a
	// protocol version, and a length.
	RecordHeader [5]byte

	// Each handshake message starts with a type and a length.
	HandshakeHeader [4]byte

	// A protocol version of "3,3" (meaning TLS 1.2) is given. Because middleboxes have been created and widely deployed
	// that do not allow protocol versions that they do not recognize, the TLS 1.3 session must be disguised as a TLS
	// 1.2 session.
	// NOTE: filed is ignored
	ClientVersion [3]byte

	// The client provides 32 bytes of random data.
	ClientRandom [32]byte

	// In previous versions of TLS the client could provide an ID of a previously negotiated session, which allows the
	// server and client to skip the time and cost of negotiating new keys. In TLS 1.3 this "session resume" is done via
	// the more flexible PSK (pre-shared keys) mechanism, so this field is no longer needed for that purpose.
	// NOTE: field is ignored
	SessionID [33]byte

	// The client provides an ordered list of which cipher suites it will support for encryption. The list is in the
	// order preferred by the client, with highest preference first.
	CipherSuites [8]byte

	// Previous versions of TLS supported compression, which was found to leak information about the encrypted data
	// allowing it to be read
	// NOTE: field is ignored
	CompressionMethods [2]byte

	// The length of the extension part
	ExtensionsLength uint16
}
