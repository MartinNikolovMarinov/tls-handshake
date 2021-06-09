package ecdhcrypto

type ECDHCrypto interface {
	GenerateSignedKey(cfg *GenKeyConfig) (pkey, cert []byte, err error)
}