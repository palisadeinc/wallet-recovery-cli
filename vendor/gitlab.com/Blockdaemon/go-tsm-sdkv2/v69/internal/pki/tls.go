package pki

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"gitlab.com/Blockdaemon/go-tsm-sdkv2/v69/internal/random"
	"math/big"
	"strconv"
	"strings"
	"time"
)

var (
	minTLSVersion   = uint16(tls.VersionTLS12)
	maxTLSVersion   = uint16(tls.VersionTLS13)
	tlsCipherSuites = []uint16{
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	}
	oidStaticPlayers = asn1.ObjectIdentifier{2, 25, 1692424408}
)

func NewTLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion:         minTLSVersion,
		MaxVersion:         maxTLSVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: false,
	}
}

func NewTLSConfigWithCustomVerification(f func(connectionState tls.ConnectionState) error) *tls.Config {
	return &tls.Config{
		MinVersion:         minTLSVersion,
		MaxVersion:         maxTLSVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: true,
		VerifyConnection:   f,
	}
}

func NewTLSConfigWithClientSessionCache() *tls.Config {
	return &tls.Config{
		MinVersion:         minTLSVersion,
		MaxVersion:         maxTLSVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: false,
		ClientSessionCache: tls.NewLRUClientSessionCache(512),
	}
}

func NewTLSConfigWithCustomVerificationWithClientSessionCache(f func(connectionState tls.ConnectionState) error) *tls.Config {
	return &tls.Config{
		MinVersion:         minTLSVersion,
		MaxVersion:         maxTLSVersion,
		CipherSuites:       tlsCipherSuites,
		InsecureSkipVerify: true,
		VerifyConnection:   f,
		ClientSessionCache: tls.NewLRUClientSessionCache(512),
	}
}

func CreateSelfSignedTLSCertificate(privateKey crypto.Signer, commonName string, staticPlayers ...int) (tls.Certificate, error) {
	startTime := time.Date(2013, 3, 20, 0, 0, 0, 0, time.UTC)
	endTime := time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    startTime,
		NotAfter:     endTime,
	}

	if len(staticPlayers) > 0 {
		staticPlayerIDs := make([]string, len(staticPlayers))
		for i := range staticPlayers {
			staticPlayerIDs[i] = strconv.Itoa(staticPlayers[i])
		}
		tpl.ExtraExtensions = []pkix.Extension{{
			Id:    oidStaticPlayers,
			Value: []byte(strings.Join(staticPlayerIDs, ",")),
		}}
	}

	x509Certificate, err := x509.CreateCertificate(random.Reader, tpl, tpl, privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{x509Certificate}, PrivateKey: privateKey}, nil
}

func CertificateContainsStaticPlayer(certificate *x509.Certificate, value int) bool {
	for _, extension := range certificate.Extensions {
		if extension.Id.Equal(oidStaticPlayers) {
			valueString := strconv.Itoa(value)
			for _, fixedPlayer := range strings.Split(string(extension.Value), ",") {
				if fixedPlayer == valueString {
					return true
				}
			}
			return false
		}
	}

	return false
}
