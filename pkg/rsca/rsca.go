package rsca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"time"

	"github.com/pkg/errors"
)

func IssueClientCertificate(cacert *x509.Certificate, cakey *rsa.PrivateKey, pub *rsa.PublicKey) (*x509.Certificate, error) {
	now := time.Now()

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	commonName, err := fingerprint(pub)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			// SerialNumber: uuid.New().String(),
			CommonName: commonName,
		},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24 * 3650),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, cacert, pub, cakey)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	cert, err := x509.ParseCertificate(certDER)
	return cert, errors.WithStack(err)
}

func fingerprint(pub *rsa.PublicKey) (string, error) {
	data, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", errors.WithStack(err)
	}
	fp := sha256.Sum256(data)
	return hex.EncodeToString(fp[:]), nil
}

// Parse from PEM
func ParsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	return priv, errors.WithStack(err)
}

// Parse from PEM
func ParsePublicKey(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	rsapub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not RSA public key")
	}
	return rsapub, nil
}

// Parse from PEM
func ParseCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, errors.WithStack(err)
}
