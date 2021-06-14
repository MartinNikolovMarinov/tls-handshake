package extensions

import (
	"testing"
)

func TestParseKeyShareExtension(t *testing.T) {
	var buf []byte = []byte{
		0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1,
		0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65,
		0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,
	}

	share, err := ParseKeyShareExtension(buf)
	if err != nil {
		t.Fatalf("ParseKeyShareExtension is broken")
	}

	shareBin := share.ToBinary()
	v := string(shareBin) == string(buf[:])
	if !v {
		t.Fatalf("ParseKeyShareExtension.ToBinary is broken")
	}
}

func TestParseSupporteVersionsExtension(t *testing.T) {
	var buf []byte = []byte{0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04}

	sve, err := ParseSupporteVersionsExtension(buf)
	if err != nil {
		t.Fatalf("ParseSupporteVersionsExtension is broken")
	}

	sveBin := sve.ToBinary()
	v := string(sveBin) == string(buf[:])
	if !v {
		t.Fatalf("ParseSupporteVersionsExtension.ToBinary is broken")
	}
}

func TestParseExtensions(t *testing.T) {
	var buf []byte = []byte{
		// KeyShare:
		0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1,
		0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65,
		0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54,

		// SupporteVersions
		0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04,
	}

	exts, err := ParseExtensions(buf[:], uint16(len(buf)))
	if err != nil || len(exts) != 2 {
		t.Fatalf("ParseExtensions is broken")
	}

	keyShareExt := FindExtension(exts, KeyShareType)
	if keyShareExt == nil {
		t.Fatalf("FindExtension is broken")
	}

	suppVerExt := FindExtension(exts, SupporteVersionsType)
	if suppVerExt == nil {
		t.Fatalf("FindExtension is broken")
	}

	keyShareExtBin := keyShareExt.ToBinary()
	v := string(keyShareExtBin) == string(buf[:keyShareExt.GetFullExtLen()])
	if !v {
		t.Fatalf("ToBinary or GetFullExtLen is broken in KeyShare")
	}

	suppVerExtBin := suppVerExt.ToBinary()
	start := keyShareExt.GetFullExtLen()
	end := start + suppVerExt.GetFullExtLen()
	v = string(suppVerExtBin) == string(buf[start:end])
	if !v {
		t.Fatalf("ToBinary or GetFullExtLen is broken in SupporteVersions")
	}
}
