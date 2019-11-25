package rsca

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"runtime"
	"testing"
)

func loadTestPEM(fn string) ([]byte, error) {
	_, file, _, _ := runtime.Caller(0)
	file, _ = filepath.Abs(
		fmt.Sprintf("%s/../../test-data/%s", filepath.Dir(file), fn),
	)
	return ioutil.ReadFile(file)
}

func TestIssueClientCertificate(t *testing.T) {
	cacertPEM, _ := loadTestPEM("ca.cert")
	cakeyPEM, _ := loadTestPEM("ca.key")

	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("%v", err)
	}
	cacert, err := ParseCertificate(cacertPEM)
	if err != nil {
		t.Errorf("%v", err)
	}
	cakey, err := ParsePrivateKey(cakeyPEM)
	if err != nil {
		t.Errorf("%v", err)
	}

	cert, err := IssueClientCertificate(cacert, cakey, &priv.PublicKey)
	if err != nil {
		t.Errorf("%v", err)
	}

	t.Logf("SerialNumber: %v", cert.SerialNumber)
	t.Logf("Issuer: %v", cert.Issuer)
	t.Logf("Subject: %v", cert.Subject)

	// data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	// t.Logf("%s", string(data))
}
