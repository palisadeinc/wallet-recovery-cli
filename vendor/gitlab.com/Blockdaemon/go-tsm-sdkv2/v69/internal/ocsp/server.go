package ocsp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/ocsp"
	"net"
	"net/http"
	"sync"
	"time"
)

type Server struct {
	issuerCert, responderCert    *x509.Certificate
	rootCerts, intermediateCerts *x509.CertPool
	signer                       crypto.Signer
	revoked                      map[string]bool
	revokedLock                  sync.Mutex
	httpListener                 net.Listener
	httpServer                   *http.Server
}

func NewServer(issuerCert, responderCert *x509.Certificate, privateKey crypto.PrivateKey) (*Server, error) {
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer")
	}

	rootCerts := x509.NewCertPool()
	rootCerts.AddCert(issuerCert)
	intermediateCerts := x509.NewCertPool()

	return &Server{
		issuerCert:        issuerCert,
		responderCert:     responderCert,
		signer:            signer,
		revoked:           map[string]bool{},
		rootCerts:         rootCerts,
		intermediateCerts: intermediateCerts,
	}, nil
}

func (s *Server) Run(port int) error {
	var err error
	s.httpListener, err = net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return err
	}

	handler := mux.NewRouter()
	handler.HandleFunc("/", s.ocspRequestHandler)

	s.httpServer = &http.Server{
		Handler: handler,
	}

	go func() {
		if err := s.httpServer.Serve(s.httpListener); !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("OCSP server error: %s", err)
		}
	}()

	return nil
}

func (s *Server) Stop() error {
	if s.httpServer != nil {
		timeoutCtx, cancel := context.WithTimeout(context.TODO(), 10*time.Second)
		defer cancel()
		if err := s.httpServer.Shutdown(timeoutCtx); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) Revoke(cert *x509.Certificate) error {
	verifiedChains, err := cert.Verify(x509.VerifyOptions{
		Intermediates: s.intermediateCerts,
		Roots:         s.rootCerts,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return fmt.Errorf("could not verify certificate: %s", err)
	}
	s.revokedLock.Lock()
	s.revoked[verifiedChains[0][0].SerialNumber.String()] = true
	s.revokedLock.Unlock()
	return nil
}

func (s *Server) ocspRequestHandler(w http.ResponseWriter, r *http.Request) {
	b := new(bytes.Buffer)
	_, err := b.ReadFrom(r.Body)
	if err != nil || b.Len() == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	req, err := ocsp.ParseRequest(b.Bytes())
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err = asn1.Unmarshal(s.issuerCert.RawSubjectPublicKeyInfo, &publicKeyInfo); err != nil {
		fmt.Println("OCSP Server:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	h := req.HashAlgorithm.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	issuerKeyHash := h.Sum(nil)

	h.Reset()
	h.Write(s.issuerCert.RawSubject)
	issuerNameHash := h.Sum(nil)

	status := ocsp.Good
	var revokedAt time.Time
	var revocationReason int
	if !bytes.Equal(issuerNameHash, req.IssuerNameHash) || !bytes.Equal(issuerKeyHash, req.IssuerKeyHash) {
		status = ocsp.Unknown
	}
	s.revokedLock.Lock()
	isRevoked := s.revoked[req.SerialNumber.String()]
	s.revokedLock.Unlock()
	if isRevoked {
		status = ocsp.Revoked
		revokedAt = time.Now()
		revocationReason = ocsp.PrivilegeWithdrawn
	}

	template := ocsp.Response{
		Status:           status,
		SerialNumber:     req.SerialNumber,
		Certificate:      s.responderCert,
		ThisUpdate:       time.Now().AddDate(0, 0, -1).UTC(),
		NextUpdate:       time.Now().AddDate(0, 0, 1).UTC(),
		RevokedAt:        revokedAt,
		RevocationReason: revocationReason,
		IssuerHash:       req.HashAlgorithm,
	}

	resp, err := ocsp.CreateResponse(s.issuerCert, s.responderCert, template, s.signer)
	if err != nil {
		fmt.Println("OCSP Server:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/ocsp-response")
	_, err = w.Write(resp)
	if err != nil {
		fmt.Println("OCSP Server:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
