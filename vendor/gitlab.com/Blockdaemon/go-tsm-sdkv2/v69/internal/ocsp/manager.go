package ocsp

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrNotSupported = errors.New("certificate does not support OCSP validation")

type Manager struct {
	overrideURL              string
	validateLeafOnly         bool
	requireStapling          bool
	hashAlgorithm            crypto.Hash
	createInternalHttpClient sync.Once
	internalHttpClient       *http.Client
	cache                    map[string]*cachedResponse
	cacheTTL                 time.Duration
	cacheLock                sync.Mutex
}

type cachedResponse struct {
	isReady    bool
	response   *ocsp.Response
	validUntil time.Time
	lock       sync.Mutex
}

func NewManager(validateLeafOnly, requireStapling bool, responderURL string, hashAlgorithm string, cacheTTL time.Duration) (*Manager, error) {
	if responderURL != "" && !strings.HasPrefix(responderURL, "http://") && !strings.HasPrefix(responderURL, "https://") {
		return nil, fmt.Errorf("only http(s) responder URLs are supported")
	}

	if hashAlgorithm == "" {
		hashAlgorithm = "SHA-256"
	}
	hash, err := getHashAlgorithm(hashAlgorithm)
	if err != nil {
		return nil, err
	}

	if cacheTTL < 0 {
		cacheTTL = 0
	}

	return &Manager{
		overrideURL:      responderURL,
		validateLeafOnly: validateLeafOnly,
		requireStapling:  requireStapling,
		hashAlgorithm:    hash,
		cache:            map[string]*cachedResponse{},
		cacheTTL:         cacheTTL,
		cacheLock:        sync.Mutex{},
	}, nil
}

func (m *Manager) httpClient() *http.Client {
	m.createInternalHttpClient.Do(func() {
		m.internalHttpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		}
	})
	return m.internalHttpClient
}

func (m *Manager) ValidateTLSConnection(state *tls.ConnectionState) error {
	verifiedChain := shortestCertificateChain(state.VerifiedChains)
	if verifiedChain == nil || len(verifiedChain) < 2 {
		// No certificate and self-signed certificates are always valid from a revocation point of view
		return nil
	}

	for i := 0; i < len(verifiedChain)-1; i++ {
		if m.validateLeafOnly && i > 0 {
			break
		}

		cert := verifiedChain[i]
		issuer := verifiedChain[i+1]

		var stapledOCSPResponse []byte
		if i == 0 {
			// Only the leaf certificate can be stapled
			mustStaple, err := m.mustStaple(cert)
			if err != nil {
				return err
			}
			if mustStaple && len(state.OCSPResponse) == 0 {
				return fmt.Errorf("no stapled OCSP response, but must staple is set")
			}
			stapledOCSPResponse = state.OCSPResponse
		}

		ocspResponse, err := m.fetchOCSPResponse(cert, issuer, stapledOCSPResponse, m.requireStapling)
		if err != nil {
			return err
		}
		if err = m.validateOCSPResponse(ocspResponse); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) StapleCertificate(cert *tls.Certificate, roots *x509.CertPool) (func() (*tls.Certificate, error), error) {
	if roots == nil {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("missing root CAs: %w", err)
		}
	}

	verifiedChains, err := buildVerifiedCertificateChain(cert, roots)
	if err != nil {
		return nil, fmt.Errorf("error building verified certificate chain: %w", err)
	}
	verifiedChain := shortestCertificateChain(verifiedChains)

	return func() (*tls.Certificate, error) {
		ocspResponse, err := m.fetchOCSPResponse(verifiedChain[0], verifiedChain[1], nil, false)
		if err != nil {
			return nil, fmt.Errorf("error fetching OCSP response: %w", err)
		}
		if err = m.validateOCSPResponse(ocspResponse); err != nil {
			return nil, err
		}
		cert.OCSPStaple = ocspResponse.Raw
		return cert, nil
	}, nil
}

func (m *Manager) fetchOCSPResponse(cert, issuer *x509.Certificate, stapledOCSPResponse []byte, requireStapling bool) (*ocsp.Response, error) {
	cacheKey := fmt.Sprintf("%d %s", cert.SerialNumber, cert.Issuer)

	m.cacheLock.Lock()
	resp, ok := m.cache[cacheKey]
	if !ok {
		resp = &cachedResponse{}
		m.cache[cacheKey] = resp
	}
	m.cacheLock.Unlock()

	resp.lock.Lock()
	if resp.isReady && time.Now().Before(resp.validUntil) {
		result := resp.response
		resp.lock.Unlock()
		return result, nil
	}
	defer resp.lock.Unlock()

	// The response is not ready (or expired) so we should create it

	// First try to use the stapled response

	var ocspResponse *ocsp.Response
	if len(stapledOCSPResponse) > 0 {
		ocspResp, err := ocsp.ParseResponseForCert(stapledOCSPResponse, cert, issuer)
		if err != nil {
			return nil, fmt.Errorf("error parsing stapled OCSP response: %w", err)
		}
		ocspResponse = ocspResp
	}

	// If there was no stapled response, then we need to fetch it from the OCSP responder

	if ocspResponse == nil {
		if requireStapling {
			return nil, fmt.Errorf("no stapled OCSP response, but require stapling is enabled")
		}

		responderURL, err := m.responderURL(cert)
		if err != nil {
			return nil, fmt.Errorf("error getting OCSP responder URL: %w", err)
		}
		if responderURL != "" {
			ocspResp, err := m.callOCSPResponder(responderURL, cert, issuer)
			if err != nil {
				return nil, fmt.Errorf("call OCSP responder: %w", err)
			}
			ocspResponse = ocspResp
		} else {
			// No responder URL and no override URL configured. We cannot do OCSP validation for this certificate
			return nil, ErrNotSupported
		}
	}

	// We have an OCSP response, so update the cache

	resp.isReady = true
	resp.response = ocspResponse
	resp.validUntil = time.Now().Add(m.cacheTTL)
	if m.cacheTTL == 0 || ocspResponse.NextUpdate.Before(resp.validUntil) {
		resp.validUntil = ocspResponse.NextUpdate
	}
	return ocspResponse, nil
}

func (m *Manager) callOCSPResponder(responderURL string, cert, issuer *x509.Certificate) (*ocsp.Response, error) {
	ocspURL, err := url.Parse(responderURL)
	if err != nil {
		return nil, fmt.Errorf("malformed responder URL: %w", err)
	}

	buffer, err := ocsp.CreateRequest(cert, issuer, &ocsp.RequestOptions{Hash: m.hashAlgorithm})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(http.MethodPost, responderURL, bytes.NewBuffer(buffer))
	if err != nil {
		return nil, fmt.Errorf("error creating HTTP request: %w", err)
	}
	req.Header.Add("Content-Type", "application/ocsp-request")
	req.Header.Add("Accept", "application/ocsp-response")
	req.Header.Add("host", ocspURL.Host)

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error calling OCSP responder: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading OCSP response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("call to OCSP responder failed with status %s", resp.Status)
	}
	ocspResponse, err := ocsp.ParseResponseForCert(respBody, cert, issuer)
	if err != nil {
		return nil, fmt.Errorf("error parsing OCSP response: %w", err)
	}
	timeNow := time.Now()
	if timeNow.Before(ocspResponse.ThisUpdate) {
		return nil, fmt.Errorf("OCSP response was made in the future")
	}
	if timeNow.After(ocspResponse.NextUpdate) {
		return nil, fmt.Errorf("timestap error: Not the latest OCSP response")
	}
	return ocspResponse, nil
}

func (m *Manager) validateOCSPResponse(ocspResponse *ocsp.Response) error {
	if ocspResponse.Status == ocsp.Good {
		return nil
	}
	var statusText string
	switch ocspResponse.Status {
	case ocsp.Good:
		statusText = "Good"
	case ocsp.Revoked:
		statusText = "Revoked"
	case ocsp.Unknown:
		statusText = "Unknown"
	case ocsp.ServerFailed:
		statusText = "ServerFailed"
	default:
		statusText = fmt.Sprintf("Unknown (%d)", ocspResponse.Status)
	}
	return fmt.Errorf("certificate validation failed with OCSP status: %s", statusText)
}

func (m *Manager) responderURL(cert *x509.Certificate) (string, error) {
	if m.overrideURL != "" {
		return m.overrideURL, nil
	}

	if len(cert.OCSPServer) == 0 {
		return "", nil
	}

	var ocspResponderURL string
	for _, s := range cert.OCSPServer {
		if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
			ocspResponderURL = s
			break
		}
	}

	if ocspResponderURL == "" {
		return "", fmt.Errorf("no http(s) OCSP responders found in certificate")
	}

	return ocspResponderURL, nil
}

func (m *Manager) mustStaple(cert *x509.Certificate) (bool, error) {
	const StatusRequestExtension = 5
	var MustStapleValue, _ = asn1.Marshal([]int{StatusRequestExtension})
	var MustStapleOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24}

	mustStaple := false
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(MustStapleOID) {
			if bytes.Equal(ext.Value, MustStapleValue) {
				mustStaple = true
			} else {
				// Technically the value is a DER encoded SEQUENCE OF INTEGER, so there might be more than one. This
				// will probably never be the case since the RFC only defines one value, but still...
				var tlsExts []int
				_, err := asn1.Unmarshal(ext.Value, &tlsExts)
				if err != nil {
					return false, fmt.Errorf("malformed must staple extension: %w", err)
				}
				for _, tlsExt := range tlsExts {
					if tlsExt == StatusRequestExtension {
						mustStaple = true
						break
					}
				}
			}
			break
		}
	}
	return mustStaple, nil
}

func buildVerifiedCertificateChain(cert *tls.Certificate, roots *x509.CertPool) ([][]*x509.Certificate, error) {
	if len(cert.Certificate) == 0 {
		return nil, fmt.Errorf("no certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("error parsing leaf certificate: %w", err)
	}
	intermediates := x509.NewCertPool()
	for i := 1; i < len(cert.Certificate); i++ {
		intermediate, err := x509.ParseCertificate(cert.Certificate[i])
		if err != nil {
			return nil, fmt.Errorf("error parsing intermediate certificate: %w", err)
		}
		intermediates.AddCert(intermediate)
	}

	verifiedChains, err := leaf.Verify(x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("error verifying certificate: %w", err)
	}
	return verifiedChains, nil
}

func shortestCertificateChain(verifiedChains [][]*x509.Certificate) []*x509.Certificate {
	if len(verifiedChains) == 0 {
		return nil
	}
	verifiedChain := verifiedChains[0]
	for i := 1; i < len(verifiedChains); i++ {
		if len(verifiedChains[i]) < len(verifiedChain) {
			verifiedChain = verifiedChains[i]
		}
	}
	return verifiedChain
}

func getHashAlgorithm(h string) (crypto.Hash, error) {
	var hash crypto.Hash
	switch h {
	case "SHA-1", "SHA1":
		hash = crypto.SHA1
	case "SHA-224", "SHA224":
		hash = crypto.SHA224
	case "SHA-256", "SHA256":
		hash = crypto.SHA256
	case "SHA-384", "SHA384":
		hash = crypto.SHA384
	case "SHA-512", "SHA512":
		hash = crypto.SHA512
	default:
		return hash, fmt.Errorf("unsupported hash algorithm: %s", h)
	}
	if !hash.Available() {
		return hash, fmt.Errorf("hash algorithm not available: %s", h)
	}
	return hash, nil
}
