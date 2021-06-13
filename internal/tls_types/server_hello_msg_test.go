package tlstypes

import "testing"

func TestParseServerHelloMsg(t *testing.T) {
	var buf []byte = []byte{
		0x16, 0x03, 0x04, 0x00, 0x7a, 0x02, 0x00, 0x00, 0x76, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76,
		0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x20, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9,
		0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb,
		0xfc, 0xfd, 0xfe, 0xff, 0x13, 0x01, 0x00, 0x00, 0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9f,
		0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b,
		0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15, 0x00, 0x2b, 0x00, 0x02, 0x03,
		0x04,
	}

	r, err := ParseRecord(buf)
	if err != nil {
		t.Fatalf("ParseRecord is broken")
	}

	recBin := r.ToBinary()
	v := string(recBin) == string(buf)
	if !v {
		t.Fatalf("Record.ToBinary is broken")
	}

	hm, err := ParseServerHelloMsg(r.Data)
	if err != nil {
		t.Fatalf("ParseServerHelloMsg is broken")
	}

	binHm := hm.ToBinary()
	v = string(binHm) == string(buf[RecordHeaderByteSize:])
	if !v {
		t.Fatalf("ParseServerHelloMsg.ToBinary is broken")
	}

	hm.Length = 0
	binHm = hm.ToBinary()
	v = string(binHm) == string(buf[RecordHeaderByteSize:])
	if !v {
		t.Fatalf("ParseServerHelloMsg.ToBinary is broken when Length is 0")
	}
}