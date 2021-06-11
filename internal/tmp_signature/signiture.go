package signature

// FIXME: might want to generate self sign signature and validate keys with it. Or Just remove this package.

// type GenKeyConfig struct {
// 	// Hosts is a Comma-separated hostnames and IPs to generate a certificate for
// 	Hosts        string
// 	Organization []string
// 	ValidFrom    time.Time
// 	ValidFor     time.Duration
// 	// IsCA denotes whether this cert should be its own Certificate Authority
// 	IsCA bool
// 	// CurveType denotes the ECDSA curve to use to generate a key
// 	CurveType ECDHCurveType
// }

// func (ec *ecdhCrypto) GenerateSignedKey(cfg *GenKeyConfig) (pkey, cert []byte, err error) {
// 	var pubkeyCurve elliptic.Curve

// 	switch cfg.CurveType {
// 	case Secp256r1:
// 		pubkeyCurve = elliptic.P256()
// 	case Secp384r1:
// 		pubkeyCurve = elliptic.P384()
// 	case Secp521r1:
// 		pubkeyCurve = elliptic.P521()
// 	default:
// 		return nil, nil, errors.New("Unsupported ECDHCurveSize")
// 	}

// 	privateKey := new(ecdsa.PrivateKey)
// 	if privateKey, err = ecdsa.GenerateKey(pubkeyCurve, rand.Reader); err != nil {
// 		return nil, nil, err
// 	}

// 	// KeyUsage bits set in the x509.Certificate template
// 	keyUsage := x509.KeyUsageDigitalSignature
// 	notBefore := cfg.ValidFrom
// 	notAfter := notBefore.Add(cfg.ValidFor)
// 	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
// 	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	template := x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject: pkix.Name{
// 			Organization: cfg.Organization,
// 		},
// 		NotBefore:             notBefore,
// 		NotAfter:              notAfter,
// 		KeyUsage:              keyUsage,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 	}

// 	hosts := strings.Split(cfg.Hosts, ",")
// 	for _, h := range hosts {
// 		if ip := net.ParseIP(h); ip != nil {
// 			template.IPAddresses = append(template.IPAddresses, ip)
// 		} else {
// 			template.DNSNames = append(template.DNSNames, h)
// 		}
// 	}

// 	if cfg.IsCA {
// 		template.IsCA = true
// 		template.KeyUsage |= x509.KeyUsageCertSign
// 	}

// 	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
// 	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	encodedPKeyBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})

// 	return encodedPKeyBytes, certBytes, nil
// }

// func (ec *ecdhCrypto) Sign(privateKey *ecdsa.PrivateKey, reader io.Reader) error {
// 	// h := md5.New()
// 	// r := big.NewInt(0)
// 	// s := big.NewInt(0)

// 	// io.WriteString(h, "This is a message to be signed and verified by ECDSA!")
// 	// signhash := h.Sum(nil)
// 	// r, s, err := ecdsa.Sign(rand.Reader, privateKey, signhash)
// 	// if err != nil {
// 	// 	return err
// 	// }

// 	// signature := r.Bytes()
// 	// signature = append(signature, s.Bytes()...)

// 	// fmt.Printf("Signature : %x\n", signature)
// 	return nil
// }

// // Verify
// verifystatus := ecdsa.Verify(&pubkey, signhash, r, s)
// fmt.Println(verifystatus) // should be true
