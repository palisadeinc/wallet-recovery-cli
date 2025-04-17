package tsm

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// WithMTLSAuthentication returns a configuration usable for creating a TSMClient on a node which accepts the provided clientCert.
// serverPKIXPublicKey is optional. If the value is niot nil, it means that the client (you)
// will only accept TLS connections from servers with the provided publicKey (certificate)
func (c Configuration) WithMTLSAuthentication(clientKeyPath, clientCertPath string, serverPKIXPublicKey []byte) (*Configuration, error) {

	certificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("error loading client key pair: %w", err)
	}

	authenticator := newMTLSAuthenticator(certificate, serverPKIXPublicKey)
	c.authenticator = &authenticator
	return &c, nil
}

// MTLSAuthenticator is used for authenticating the SDK against an MPC node using 2-way TLS (mTLS).
//
// Only used internally.
type MTLSAuthenticator struct {
	certificate tls.Certificate
	publicKey   []byte
}

func newMTLSAuthenticator(certificate tls.Certificate, publicKey []byte) Authenticator {
	return MTLSAuthenticator{certificate: certificate, publicKey: publicKey}
}

func (a MTLSAuthenticator) unauthorized(transport http.RoundTripper) error {
	return errors.New("unauthorized certificate")
}

func (a MTLSAuthenticator) authenticateRequest(request *http.Request, transport http.RoundTripper) (*http.Request, error) {
	return request, nil
}

func (a MTLSAuthenticator) newNode(url url.URL) (*node, error) {
	return newURLNodeWithTLSPinnedPublicKey(url, a.certificate, a.publicKey)
}
