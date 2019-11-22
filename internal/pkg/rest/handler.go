package rest

import (
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"net/http"

	"github.com/erning/rsca/pkg/rsca"
)

type Handler struct {
	cacert *x509.Certificate
	cakey  *rsa.PrivateKey
}

func NewHandler(cacert *x509.Certificate, cakey *rsa.PrivateKey) *Handler {
	handler := &Handler{
		cacert: cacert,
		cakey:  cakey,
	}
	return handler
}

func NewHandlerFromPEM(cacertPEM []byte, cakeyPEM []byte) (*Handler, error) {
	cacert, err := rsca.ParseCertificate(cacertPEM)
	if err != nil {
		return nil, err
	}
	cakey, err := rsca.ParsePrivateKey(cakeyPEM)
	if err != nil {
		return nil, err
	}
	return NewHandler(cacert, cakey), nil
}

func (h *Handler) HandleIssueClientCertificate(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.Body == nil {
		http.Error(w, "Bad request", 400)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	pub, err := rsca.ParsePublicKey(body)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	cert, err := rsca.IssueClientCertificate(h.cacert, h.cakey, pub)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}

	_, _ = w.Write(cert.Raw)
}
