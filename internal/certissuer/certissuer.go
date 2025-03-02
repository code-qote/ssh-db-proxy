package certissuer

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

const maxCacheSize = 1000

type CertIssuer struct {
	ca   *x509.Certificate
	pkey *rsa.PrivateKey

	mu    sync.RWMutex
	cache map[string]tls.Certificate
}

func NewCertIssuer(caFilePath string, caPrivateKeyPath string) (*CertIssuer, error) {
	ca, err := parseCertificate(caFilePath)
	if err != nil {
		return nil, err
	}
	pkey, err := parsePrivateKey(caPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	return &CertIssuer{ca: ca, pkey: pkey, cache: make(map[string]tls.Certificate)}, nil
}

func (c *CertIssuer) Issue(commonName string) (tls.Certificate, error) {
	now := time.Now()

	c.mu.RLock()
	if cert, ok := c.cache[commonName]; ok && now.Before(cert.Leaf.NotAfter) {
		c.mu.RUnlock()
		return cert, nil
	}
	c.mu.RUnlock()

	max := new(big.Int)
	max.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(max, big.NewInt(1))
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return tls.Certificate{}, err
	}

	cert := &x509.Certificate{
		SerialNumber: n,
		Subject: pkix.Name{
			Organization: []string{"DBProxy"},
			CommonName:   commonName,
		},
		NotBefore:   now,
		NotAfter:    now.Add(1 * time.Minute),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certPKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return tls.Certificate{}, err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, c.ca, &certPKey.PublicKey, c.pkey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := new(bytes.Buffer)
	if err := pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		return tls.Certificate{}, err
	}

	certPKeyPEM := new(bytes.Buffer)
	if err := pem.Encode(certPKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPKey),
	}); err != nil {
		return tls.Certificate{}, err
	}

	tlsCert, err := tls.X509KeyPair(certPEM.Bytes(), certPKeyPEM.Bytes())
	if err != nil {
		return tls.Certificate{}, err
	}

	c.addToCache(commonName, tlsCert, now)

	return tlsCert, nil
}

func (c *CertIssuer) addToCache(commonName string, cert tls.Certificate, now time.Time) {
	c.mu.Lock()
	if _, ok := c.cache[commonName]; !ok && len(c.cache)+1 >= maxCacheSize {
		outdatedKeys := make([]string, 0, len(c.cache))
		for k, v := range c.cache {
			if now.After(v.Leaf.NotAfter) {
				outdatedKeys = append(outdatedKeys, k)
			}
		}
		for _, k := range outdatedKeys {
			delete(c.cache, k)
		}
	}
	c.cache[commonName] = cert
	c.mu.Unlock()
}

func parseCertificate(filename string) (*x509.Certificate, error) {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	return x509.ParseCertificate(block.Bytes)
}

func parsePrivateKey(filename string) (*rsa.PrivateKey, error) {
	caPrivateKeyBytes, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(caPrivateKeyBytes)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	pkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pkey.(*rsa.PrivateKey), nil
}
