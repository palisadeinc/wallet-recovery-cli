package tsm

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/ocsp"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/pki"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v70/internal/transport"
	"net/http"
	"net/url"
	"os"
	"time"
)

type Configuration struct {
	// The URL of the MPC node to which this client is connected.
	URL string

	rootCAFile           string
	serverPKIXPublicKey  []byte
	ocspConfig           *OCSPConfiguration
	authenticatorBuilder func() (*Authenticator, error)
}

// WithRootCAFile specifies a file containing PEM certificates of the trusted root CAs used to validate the MPC node
// certificate. If not set, the system certificate store is used.
func (c Configuration) WithRootCAFile(rootCAFile string) *Configuration {
	c.rootCAFile = rootCAFile
	return &c
}

// WithPublicKeyPinning sets the expected MPC node public key in PKIX, ASN.1 DER form. If the TSM node presents a different
// public key, the connection will fail. Setting this will disable OCSP validation and all other certificate checks.
func (c Configuration) WithPublicKeyPinning(serverPKIXPublicKey []byte) *Configuration {
	c.serverPKIXPublicKey = serverPKIXPublicKey
	return &c
}

// WithOCSPValidation enables OCSP validation of the MPC node certificate.
func (c Configuration) WithOCSPValidation(config *OCSPConfiguration) *Configuration {
	c.ocspConfig = config
	return &c
}

type OCSPConfiguration struct {
	// Require the TSM node to send a stapled OCSP response, otherwise validation will fail.
	RequireStapling bool
	// If true then only the leaf certificate is validated. Otherwise, the entire chain is validated.
	ValidateLeafOnly bool
	// Lifetime of cached OCSP responses, e.g "1h30m". A value of 0 means that ValidUntil from the OCSP response
	// is used, otherwise the value of CacheTTL is used if it comes before ValidUntil.
	CacheTTL string
	// Use this URL for all OCSP responders, regardless of what the certificate says.
	ResponderURL string
	// Use this hash algorithm for OCSP requests, usually SHA-1 or SHA-256. If empty then SHA-256 is used.
	HashAlgorithm string
}

type Client struct {
	node          *node
	keyManagement KeyManagementAPI
	wrappingKey   WrappingKeyAPI
	ecdsa         ECDSAAPI
	schnorr       SchnorrAPI
	broadcast     BroadcastAPI
	aes           AESAPI
	hmac          HMACAPI
	rsa           RSAAPI
	nodeStopper   *func() error
}

func NewClient(cfg *Configuration) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("unable to create client: URL is missing")
	}
	if cfg.authenticatorBuilder == nil {
		return nil, errors.New("unable to create client: No authentication method specified in configuration")
	}
	nodeURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %s", err)
	}

	tlsConfig := pki.NewTLSConfigWithClientSessionCache()

	var rootCAs *x509.CertPool
	if cfg.rootCAFile != "" {
		rootCAs, err = loadCertificates(cfg.rootCAFile)
		if err != nil {
			return nil, fmt.Errorf("error loading certificates: %s", err)
		}
	} else {
		rootCAs, err = x509.SystemCertPool()
		if err != nil {
			rootCAs = x509.NewCertPool()
		}
	}
	tlsConfig.RootCAs = rootCAs

	if len(cfg.serverPKIXPublicKey) > 0 {
		if err = enablePublicKeyPinning(cfg.serverPKIXPublicKey, tlsConfig); err != nil {
			return nil, fmt.Errorf("error enabling public key pinning: %s", err)
		}
	} else if cfg.ocspConfig != nil {
		if err := enableOCSPValidation(cfg.ocspConfig, tlsConfig); err != nil {
			return nil, fmt.Errorf("error enabling OCSP validation: %s", err)
		}
	}

	authenticator, err := cfg.authenticatorBuilder()
	if err != nil {
		return nil, fmt.Errorf("error creating authenticator: %s", err)
	}
	n, err := (*authenticator).newNode(*nodeURL, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %w", err)
	}

	c := &Client{node: n}
	c.createServices()

	return c, nil
}

// NewClientWithTransportAndAuthenticator creates a new client with specific communication and authentication.
//
// Only used internally.
func NewClientWithTransportAndAuthenticator(transport http.RoundTripper, authenticator Authenticator) (*Client, error) {
	n, err := newNode(transport, authenticator)
	if err != nil {
		return nil, fmt.Errorf("unable to create client: %w", err)
	}

	c := &Client{node: n}
	c.createServices()

	return c, nil
}

func (c *Client) KeyManagement() KeyManagementAPI {
	if c.keyManagement == nil {
		panic("Key management service is not enabled")
	}
	return c.keyManagement
}

func (c *Client) WrappingKey() WrappingKeyAPI {
	if c.wrappingKey == nil {
		panic("Wrapping key service is not enabled")
	}
	return c.wrappingKey
}

func (c *Client) ECDSA() ECDSAAPI {
	if c.ecdsa == nil {
		panic("ECDSA service is not enabled")
	}
	return c.ecdsa
}

func (c *Client) Schnorr() SchnorrAPI {
	if c.schnorr == nil {
		panic("Schnorr service is not enabled")
	}
	return c.schnorr
}

func (c *Client) Broadcast() BroadcastAPI {
	if c.broadcast == nil {
		panic("Broadcast service is not enabled")
	}
	return c.broadcast
}

func (c *Client) AES() AESAPI {
	if c.aes == nil {
		panic("AES service is not enabled")
	}
	return c.aes
}

func (c *Client) HMAC() HMACAPI {
	if c.hmac == nil {
		panic("HMAC service is not enabled")
	}
	return c.hmac
}

func (c *Client) RSA() RSAAPI {
	if c.rsa == nil {
		panic("RSA service is not enabled")
	}
	return c.rsa
}

// Stopper provides an external function defining how to stop an embedded MPC node.
// Only used internally.
func (c *Client) Stopper(nodeStopper func() error) {
	c.nodeStopper = &nodeStopper
}

// StopNode stops an embedded MPC node.
// Only used internally.
func (c *Client) StopNode() error {
	if c.nodeStopper == nil {
		return errors.New("no node stopper available")
	}
	return (*c.nodeStopper)()
}

func (c *Client) createServices() {
	c.keyManagement = &keyManagementService{c.node}
	c.wrappingKey = &wrappingKeyService{node: c.node, cache: &wrappingKeyCache{}}

	if c.node.info.ECDSA != transport.DISABLED {
		c.ecdsa = &ecdsaService{c.node}
	}
	if c.node.info.SCHNORR != transport.DISABLED {
		c.schnorr = &schnorrService{c.node}
	}
	if c.node.info.BROADCAST != transport.DISABLED {
		c.broadcast = &broadcastService{c.node}
	}
	if c.node.info.AES != transport.DISABLED {
		c.aes = &aesService{c.node}
	}
	if c.node.info.HMAC != transport.DISABLED {
		c.hmac = &hmacService{c.node}
	}
	if c.node.info.RSA != transport.DISABLED {
		c.rsa = &rsaService{c.node}
	}
}

func enableOCSPValidation(cfg *OCSPConfiguration, tlsConfig *tls.Config) error {
	cacheTTL, err := time.ParseDuration(cfg.CacheTTL)
	if err != nil {
		return fmt.Errorf("invalid OCSP cache TTL: %w", err)
	}
	ocspManager, err := ocsp.NewManager(cfg.ValidateLeafOnly, cfg.RequireStapling, cfg.ResponderURL, cfg.HashAlgorithm, cacheTTL)
	if err != nil {
		return err
	}
	tlsConfig.VerifyConnection = func(state tls.ConnectionState) error {
		return ocspManager.ValidateTLSConnection(&state)
	}
	return nil
}

func enablePublicKeyPinning(serverPKIXPublicKey []byte, tlsConfig *tls.Config) error {
	tlsConfig.InsecureSkipVerify = true
	tlsConfig.VerifyConnection = func(connectionState tls.ConnectionState) error {
		if !bytes.Equal(connectionState.PeerCertificates[0].RawSubjectPublicKeyInfo, serverPKIXPublicKey) {
			return fmt.Errorf("invalid public key for server")
		}
		return nil
	}
	return nil
}

func loadCertificates(certFile string) (*x509.CertPool, error) {
	if _, err := os.Stat(certFile); err != nil {
		return nil, fmt.Errorf("file does not exist: %s", certFile)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return nil, fmt.Errorf("error reading from file: %s", err)
	}

	certPool := x509.NewCertPool()
	for len(certPEM) > 0 {
		var block *pem.Block
		block, certPEM = pem.Decode(certPEM)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certPool.AddCert(cert)
	}
	return certPool, nil
}
