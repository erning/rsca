package rsca

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

var cacertPEM = `-----BEGIN CERTIFICATE-----
MIIEyjCCArICCQCC0033sv4Y6DANBgkqhkiG9w0BAQsFADAnMQswCQYDVQQGEwJD
TjELMAkGA1UECAwCU0gxCzAJBgNVBAoMAkJMMB4XDTE5MTEyMjA2NTIxNVoXDTI5
MTExOTA2NTIxNVowJzELMAkGA1UEBhMCQ04xCzAJBgNVBAgMAlNIMQswCQYDVQQK
DAJCTDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAM6yz7055u8iFifg
dY9biR62vq8eAhD6fk3w+26UDd1Ny2nVygRmDrXzEnQVHW5MHsyiyGWnf0CsskVN
La/FoORu33heChA69KSQ3WH0uE+FuECfZqLiAB+EspLqcWBEj2GynmmOtw8hBPrH
MxCPWDkVXM1bii1ZAcOGHnkrykS1Jw5c3imFz84UoV5AVONWTXTWn9eC2Is3LscX
eu1q3lwilSLErRB2NixZ/ZS1TFROZ5PrDrsvOq2/cL72s0xXo9CVurcKm1tEtFOi
cks1Hl3+jeo5ajbr44cOi7vBuWuYZ1Q7NqTLWnmYQgMT2ClvcYt9Q9C6hW9VyhaY
GCg5uS6FnXviV7ttF7S3bLsUewc1sHNttKZwO7UqCrZ7572zQqWF9z33l4eblV0p
IdNI305KfN+iICszCfT79vWSDkMn81xLh43kF4PRzNd2pK4U3kkmMkXtTZ03t5pI
1w9o/wMKFZ79i9xsCUB2pqIbz/4/sbqaKKcb4hS9clOPghCfObvZLpBopMe8VtuN
pjNMpq+cuahifETn9sl1AF+pLQX9y2D4qZk338TOq+/HFr5yKGBruTz0NPtqkxP+
2haW+VJy1iDEwAIrGA+vR5ZaeMjtOj2rLqq14hdDjYHxAwN8dpXRakOCETqajLi9
Q0O2NS6nk8DIOQ/A1i6sGLanRG0PAgMBAAEwDQYJKoZIhvcNAQELBQADggIBAHvO
EfY6WY8zggdo5D0EddgkGgZ9CDOCMvVZhy8NdXyYoBduQTRl2W3+oTxJensTBAVx
X+GC/8xQZlph6yAhwQRDvtDDFSlZaLF8ok9RP2xuNouXe9SmU+py5fCVUY5AHZ9b
wzcYAhPYQW/YMCmG/D+49qOyhifomWdOVX6ztqNDeEqRCN7Yz6NBNWR1VKnY454N
SpN2LEYb06mJoFiEMXGOZg2WkQu1E7fwc8KPcDtuDmz90OGurjDPshrRLa87uBrf
tX4lC6PJlVWe9Q8cTSJiy7KYojOZ2tnDwBxgcP4xKJKusCAShJ4GOZBGWJaK8KnC
sxtPRELnhS1U8qs0YakfzGM8yQGUuPVbPquPgguSuz5VtacJBg4g187He3Xlan5I
SWK+w+vuoad72wD0gcrSATAKGm8aXOIptNdXPzg33/VLpO3Azh+JnGaUJEHMWm4l
LFyzankbS367XmJT1uDv+nisEKrm26RC5aYjh6fX7vVQ1WPtjn69q1H6Z5Y4xlab
vGAqhwXUV8G4HAAvzFKsrRw+s6ltxB42uTwwqFBeClveHPRBRORH7A39EvxjK5qg
1ttTkFuki1WIpgSSDlgvmvJAf3ssj+h0t2o7ktbuU9/BM8fGfcrr6gI2gzfODRbi
hjdQ5L2K8lNgc8cs3pQI5KI3bnLJiQ4lh1P9OUEo
-----END CERTIFICATE-----
`

var cakeyPEM = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`

func TestIssueClientCertificate(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Errorf("%v", err)
	}
	cacert, err := ParseCertificate([]byte(cacertPEM))
	if err != nil {
		t.Errorf("%v", err)
	}
	cakey, err := ParsePrivateKey([]byte(cakeyPEM))
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
