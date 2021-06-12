package tlstypes

type TLSFieldSize uint32

const (
	RecordHeaderByteSize       TLSFieldSize = 5
	HandshakeHeaderByteSize    TLSFieldSize = 4
	VersionByteSize            TLSFieldSize = 2
	RandomByteSize             TLSFieldSize = 32
	CompressionMethodsByteSize TLSFieldSize = 2
	ExtensionsLengthByteSize   TLSFieldSize = 2
	AlertByteSize              TLSFieldSize = 2
)
