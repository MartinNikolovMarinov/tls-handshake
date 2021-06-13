package tlstypes

type TLSFieldSize uint32

const (
	RecordHeaderByteSize       TLSFieldSize = 5
	AlertByteSize              TLSFieldSize = 2

	HandshakeHeaderByteSize    TLSFieldSize = 4
	VersionByteSize            TLSFieldSize = 2
	RandomByteSize             TLSFieldSize = 32
	ExtensionsLengthByteSize   TLSFieldSize = 2
)