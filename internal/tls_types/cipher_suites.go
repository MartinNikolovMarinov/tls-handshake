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

type CipherSuites struct {
	Len    uint16
	Suites []CipherSuite
}

func ParseCipherSuites(raw [8]byte) (CipherSuites, error) {
	ret := CipherSuites{
		Suites: make([]CipherSuite, 0, 3),
		Len:    0,
	}

	ret.Len = (uint16(raw[0]) << 8) + uint16(raw[1])
	if ret.Len < 2 || ret.Len > 6 {
		return ret, errors.New("unsupported cipher suite length")
	}

	for i := 2; i < int(ret.Len) + 2; i += 2 {
		c := (uint16(raw[i]) << 8) + uint16(raw[i+1])
		switch c {
		case tls.TLS_AES_128_GCM_SHA256:
			ret.Suites = append(ret.Suites, TLS_AES_128_GCM_SHA256)
		case tls.TLS_AES_256_GCM_SHA384:
			ret.Suites = append(ret.Suites, TLS_AES_256_GCM_SHA384)
		case tls.TLS_CHACHA20_POLY1305_SHA256:
			ret.Suites = append(ret.Suites, TLS_CHACHA20_POLY1305_SHA256)
		default:
			return ret, errors.New("unsupported cipher suite")
		}
	}

	return ret, nil
}
