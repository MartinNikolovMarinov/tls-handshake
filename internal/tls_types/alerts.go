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

func ParseAlert(raw []byte) (ret Alert, err error) {
	if len(raw) < int(AlertByteSize) {
		return ret, errors.New("unsupported alert byte size")
	}

	switch AlertLevel(raw[0]) {
	case WarningAlertLevel:
		ret.Level = WarningAlertLevel
	case FatalAlertLevel:
		ret.Level = FatalAlertLevel
	default:
		return ret, errors.New("unsupported alert level")
	}

	switch AlertDescription(raw[1]) {
	case CloseNotify:
		ret.Description = CloseNotify
	case UnexpectedMessage:
		ret.Description = UnexpectedMessage
	case BadRecordMac:
		ret.Description = BadRecordMac
	case DecryptionFailedReserved:
		ret.Description = DecryptionFailedReserved
	case RecordOverflow:
		ret.Description = RecordOverflow
	case DecompressionFailure:
		ret.Description = DecompressionFailure
	case HandshakeFailure:
		ret.Description = HandshakeFailure
	case NoCertificateReserved:
		ret.Description = NoCertificateReserved
	case BadCertificate:
		ret.Description = BadCertificate
	case UnsupportedCertificate:
		ret.Description = UnsupportedCertificate
	case CertificateRevoked:
		ret.Description = CertificateRevoked
	case CertificateExpired:
		ret.Description = CertificateExpired
	case CertificateUnknown:
		ret.Description = CertificateUnknown
	case IllegalParameter:
		ret.Description = IllegalParameter
	case UnknownCa:
		ret.Description = UnknownCa
	case AccessDenied:
		ret.Description = AccessDenied
	case DecodeError:
		ret.Description = DecodeError
	case DecryptError:
		ret.Description = DecryptError
	case ExportRestrictionReserved:
		ret.Description = ExportRestrictionReserved
	case ProtocolVersion:
		ret.Description = ProtocolVersion
	case InsufficientSecurity:
		ret.Description = InsufficientSecurity
	case InternalError:
		ret.Description = InternalError
	case UserCanceled:
		ret.Description = UserCanceled
	case NoRenegotiation:
		ret.Description = NoRenegotiation
	case UnsupportedExtension:
		ret.Description = UnsupportedExtension
	default:
		return ret, errors.New("unsupported alert description")
	}

	return ret, nil
}

func MarshalAlert(rh *Alert) []byte {
	if rh == nil {
		panic(common.ImplementationErr)
	}
	raw := make([]byte, AlertByteSize)
	raw[0] = byte(rh.Level)
	raw[1] = byte(rh.Description)
	return raw
}
