package tsm

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/ocsp"
	"net/http"
	"net/url"
	"time"
)

// WithMTLSAuthentication returns a configuration that uses the provided client certificate for mTLS authentication.
// If ocspStapling is set, the client certificate will be stapled with an OCSP response.
func (c Configuration) WithMTLSAuthentication(keyFile, certFile string, ocspStapling *OCSPStaplingConfiguration) *Configuration {
	c.authenticatorBuilder = func() (*Authenticator, error) {
		clientCert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("error loading client certificate: %w", err)
		}

		var getClientCertFunc func() (*tls.Certificate, error)
		if ocspStapling != nil {
			var rootCAs *x509.CertPool
			if ocspStapling.RootCAFile != "" {
				rootCAs, err = loadCertificates(ocspStapling.RootCAFile)
				if err != nil {
					return nil, fmt.Errorf("error loading CA certificates: %w", err)
				}
			}

			cacheTTL, err := time.ParseDuration(ocspStapling.CacheTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid OCSP cache TTL: %w", err)
			}
			ocspManager, err := ocsp.NewManager(true, false, ocspStapling.ResponderURL, ocspStapling.HashAlgorithm, cacheTTL)
			if err != nil {
				return nil, fmt.Errorf("error initializing OCSP manager: %w", err)
			}
			getClientCertFunc, err = ocspManager.StapleCertificate(&clientCert, rootCAs)
			if err != nil {
				return nil, fmt.Errorf("error setting up OCSP stapling: %w", err)
			}
		} else {
			getClientCertFunc = func() (*tls.Certificate, error) {
				return &clientCert, nil
			}
		}

		authenticator := newMTLSAuthenticator(getClientCertFunc)
		return &authenticator, nil
	}
	return &c
}

type OCSPStaplingConfiguration struct {
	// PEM certificate file containing trusted root CAs used for validating the client certificate.
	// If empty, the system certificate store is used.
	RootCAFile string
	// Lifetime of cached OCSP responses, e.g "1h30m". A value of 0 means that ValidUntil from the OCSP response
	// is used, otherwise the value of CacheTTL is used if it comes before ValidUntil.
	CacheTTL string
	// Use this URL for all OCSP responders, regardless of what the certificate says.
	ResponderURL string
	// Use this hash algorithm for OCSP requests, usually SHA-1 or SHA-256. If empty then SHA-256 is used.
	HashAlgorithm string
}

// MTLSAuthenticator is used for authenticating the SDK against an MPC node using 2-way TLS (mTLS).
//
// Only used internally.
type MTLSAuthenticator struct {
	getClientCertFunc func() (*tls.Certificate, error)
}

func newMTLSAuthenticator(getClientCertFunc func() (*tls.Certificate, error)) Authenticator {
	return MTLSAuthenticator{getClientCertFunc: getClientCertFunc}
}

func (a MTLSAuthenticator) unauthorized(transport http.RoundTripper) error {
	return errors.New("unauthorized certificate")
}

func (a MTLSAuthenticator) authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error) {
	return request, nil
}

func (a MTLSAuthenticator) newNode(url url.URL, tlsConfig *tls.Config) (*node, error) {
	tlsConfig.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return a.getClientCertFunc()
	}
	return newURLNode(url, tlsConfig, a)
}
