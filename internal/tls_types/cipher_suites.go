package tlstypes

import (
	"crypto/tls"
	"errors"
)

type CipherSuite uint16

const (
	TLS_AES_128_GCM_SHA256       = CipherSuite(tls.TLS_AES_128_GCM_SHA256)
	TLS_AES_256_GCM_SHA384       = CipherSuite(tls.TLS_AES_256_GCM_SHA384)
	TLS_CHACHA20_POLY1305_SHA256 = CipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256)
)

func ParseCipherSuites(raw []byte) ([]CipherSuite, error) {
	ret := make([]CipherSuite, 0, 3)

	for i := 0; i < len(raw); i += 2 {
		c := (uint16(raw[i]) << 8) + uint16(raw[i+1])
		switch c {
		case tls.TLS_AES_128_GCM_SHA256:
			ret = append(ret, TLS_AES_128_GCM_SHA256)
		case tls.TLS_AES_256_GCM_SHA384:
			ret = append(ret, TLS_AES_256_GCM_SHA384)
		case tls.TLS_CHACHA20_POLY1305_SHA256:
			ret = append(ret, TLS_CHACHA20_POLY1305_SHA256)
		default:
			return ret, errors.New("unsupported cipher suite")
		}
	}

	return ret, nil
}
