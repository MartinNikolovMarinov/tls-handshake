package bytes

import typesizes "github.com/tls-handshake/pkg/type_sizes"

func Xor(a, b []byte) []byte {
	var (
		longer  []byte
		shorter []byte
		i       int
	)

	if len(a) > len(b) {
		longer = a
		shorter = b
	} else {
		longer = b
		shorter = a
	}

	ret := make([]byte, len(longer))
	for i = 0; i < len(shorter); i++ {
		ret[i] = shorter[i] ^ longer[i]
	}

	copy(ret[i:], longer[i:])
	return ret
}

func UInt64ToBytes(n uint64) []byte {
	var ret [typesizes.Uint64Bytes]byte
	const oneByte = 4
	ret[0] = byte(n)
	ret[1] = byte(n >> oneByte * 1)
	ret[2] = byte(n >> oneByte * 2)
	ret[3] = byte(n >> oneByte * 3)
	ret[4] = byte(n >> oneByte * 4)
	ret[5] = byte(n >> oneByte * 5)
	ret[6] = byte(n >> oneByte * 6)
	ret[7] = byte(n >> oneByte * 7)
	return ret[:]
}

func PadSlice(s []byte, v byte, to int) []byte {
	for len(s) < to {
		s = append(s, v)
	}
	return s
}