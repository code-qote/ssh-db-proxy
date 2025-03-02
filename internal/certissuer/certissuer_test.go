package certissuer

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCertIssuer_Issue(t *testing.T) {
	const (
		interCACertFile = "files/inter-ca.pem"
		interCAKeyFile  = "files/inter-ca.key"

		caCertFile = "files/chain.pem"

		commonName = "Test Common Name"
	)

	issuer, err := NewCertIssuer(interCACertFile, interCAKeyFile)
	require.NoError(t, err)

	tlsCert, err := issuer.Issue(commonName)
	require.NoError(t, err)

	caCert, err := parseCertificate(caCertFile)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	interCACert, err := parseCertificate(interCACertFile)
	require.NoError(t, err)
	inters := x509.NewCertPool()
	inters.AddCert(interCACert)

	_, err = tlsCert.Leaf.Verify(x509.VerifyOptions{
		Intermediates: inters,
		Roots:         roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	require.NoError(t, err)

	require.NotNil(t, tlsCert.Leaf)
	require.Equal(t, commonName, tlsCert.Leaf.Subject.CommonName)
}
