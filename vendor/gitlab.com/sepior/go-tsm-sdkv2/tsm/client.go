package tsm

import (
	"errors"
	"fmt"
	"gitlab.com/sepior/go-tsm-sdkv2/internal/transport"
	"net/http"
	"net/url"
)

type Configuration struct {

	// The URL of the MPC node to which this client is connected.
	URL string

	authenticator *Authenticator
}

type Client struct {
	node          *node
	keyManagement KeyManagementAPI
	wrappingKey   WrappingKeyAPI
	ecdsa         ECDSAAPI
	schnorr       SchnorrAPI
	broadcast     BroadcastAPI
	nodeStopper   *func() error
}

func NewClient(cfg *Configuration) (*Client, error) {
	if cfg.URL == "" {
		return nil, errors.New("unable to create client: URL is missing")
	}
	if cfg.authenticator == nil {
		return nil, errors.New("unable to create client: No authentication method specified in configuration")
	}

	nodeURL, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %s", err)
	}

	n, err := (*cfg.authenticator).newNode(*nodeURL)
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

// Stopper provides an external function defining how to stop an embedded MPC node.
//
// Only used internally.
func (c *Client) Stopper(nodeStopper func() error) {
	c.nodeStopper = &nodeStopper
}

// StopNode stops an embedded MPC node.
//
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
}
