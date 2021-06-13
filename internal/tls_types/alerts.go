package tlstypes

import (
	"errors"

	"github.com/tls-handshake/internal/common"
)

// Alerts as defined in RFC 5246 section 7.2

type AlertLevel uint8

const (
	WarningAlertLevel AlertLevel = 1
	FatalAlertLevel   AlertLevel = 2
)

type AlertDescription uint8

const (
	CloseNotify               AlertDescription = 0
	UnexpectedMessage         AlertDescription = 10
	BadRecordMac              AlertDescription = 20
	DecryptionFailedReserved  AlertDescription = 21
	RecordOverflow            AlertDescription = 22
	DecompressionFailure      AlertDescription = 30
	HandshakeFailure          AlertDescription = 40
	NoCertificateReserved     AlertDescription = 41
	BadCertificate            AlertDescription = 42
	UnsupportedCertificate    AlertDescription = 43
	CertificateRevoked        AlertDescription = 44
	CertificateExpired        AlertDescription = 45
	CertificateUnknown        AlertDescription = 46
	IllegalParameter          AlertDescription = 47
	UnknownCa                 AlertDescription = 48
	AccessDenied              AlertDescription = 49
	DecodeError               AlertDescription = 50
	DecryptError              AlertDescription = 51
	ExportRestrictionReserved AlertDescription = 60
	ProtocolVersion           AlertDescription = 70
	InsufficientSecurity      AlertDescription = 71
	InternalError             AlertDescription = 80
	UserCanceled              AlertDescription = 90
	NoRenegotiation           AlertDescription = 100
	UnsupportedExtension      AlertDescription = 110
)

type Alert struct {
	Level       AlertLevel
	Description AlertDescription
}

func ParseAlert(raw []byte) (*Alert, error) {
	if len(raw) < int(AlertByteSize) {
		return nil, errors.New("unsupported alert byte size")
	}

	a := &Alert{}
	switch AlertLevel(raw[0]) {
	case WarningAlertLevel:
		a.Level = WarningAlertLevel
	case FatalAlertLevel:
		a.Level = FatalAlertLevel
	default:
		return nil, errors.New("unsupported alert level")
	}

	switch AlertDescription(raw[1]) {
	case CloseNotify:
		a.Description = CloseNotify
	case UnexpectedMessage:
		a.Description = UnexpectedMessage
	case BadRecordMac:
		a.Description = BadRecordMac
	case DecryptionFailedReserved:
		a.Description = DecryptionFailedReserved
	case RecordOverflow:
		a.Description = RecordOverflow
	case DecompressionFailure:
		a.Description = DecompressionFailure
	case HandshakeFailure:
		a.Description = HandshakeFailure
	case NoCertificateReserved:
		a.Description = NoCertificateReserved
	case BadCertificate:
		a.Description = BadCertificate
	case UnsupportedCertificate:
		a.Description = UnsupportedCertificate
	case CertificateRevoked:
		a.Description = CertificateRevoked
	case CertificateExpired:
		a.Description = CertificateExpired
	case CertificateUnknown:
		a.Description = CertificateUnknown
	case IllegalParameter:
		a.Description = IllegalParameter
	case UnknownCa:
		a.Description = UnknownCa
	case AccessDenied:
		a.Description = AccessDenied
	case DecodeError:
		a.Description = DecodeError
	case DecryptError:
		a.Description = DecryptError
	case ExportRestrictionReserved:
		a.Description = ExportRestrictionReserved
	case ProtocolVersion:
		a.Description = ProtocolVersion
	case InsufficientSecurity:
		a.Description = InsufficientSecurity
	case InternalError:
		a.Description = InternalError
	case UserCanceled:
		a.Description = UserCanceled
	case NoRenegotiation:
		a.Description = NoRenegotiation
	case UnsupportedExtension:
		a.Description = UnsupportedExtension
	default:
		return nil, errors.New("unsupported alert description")
	}

	return a, nil
}

func (a *Alert) ToBinary() []byte {
	common.AssertImpl(a != nil)
	raw := make([]byte, AlertByteSize)
	raw[0] = byte(a.Level)
	raw[1] = byte(a.Description)
	return raw
}
