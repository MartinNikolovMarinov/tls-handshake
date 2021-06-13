package tlstypes

import (
	"crypto/tls"

	"github.com/tls-handshake/internal/common"
)

func MakeAlertRecord(a *Alert) *Record {
	common.AssertImpl(a != nil)
	abin := a.ToBinary()
	r := &Record{
		TLSVersion: tls.VersionTLS13,
		RecordType: AlertRecord,
		Length:     uint16(len(abin)),
		Data:       abin,
	}

	return r
}