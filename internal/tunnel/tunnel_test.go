package tunnel

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"
)

func TestTunnel(t *testing.T) {
	hostCertFile, _, _, err := generateKeys()
	require.NoError(t, err)
	_ = hostCertFile

	//tunnel, err := NewTunnel(&config.TunnelConfig{
	//	Host:               "localhost",
	//	Port:               "8080",
	//	NoClientAuth:       true,
	//	HostKeyPrivatePath: filepath.Abs(hostCertFile.Name()),
	//	UserCAPath:         "",
	//}, nil)
}

func generateKeys() (*os.File, *os.File, *os.File, error) {
	const tempDir = ""
	caPrivate, caPublic, err := generateRSAKey()
	if err != nil {
		return nil, nil, nil, err
	}
	hostPrivateKey, _, err := generateRSAKey()
	if err != nil {
		return nil, nil, nil, err
	}
	_, userPublic, err := generateRSAKey()
	if err != nil {
		return nil, nil, nil, err
	}
	sshUserPublic, err := ssh.NewPublicKey(userPublic)
	if err != nil {
		return nil, nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(caPrivate)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := newCertificate(signer, sshUserPublic)

	hostCertFile, err := os.CreateTemp(tempDir, "host-cert-*")
	if err != nil {
		return nil, nil, nil, err
	}
	pem, err := ssh.MarshalPrivateKey(hostPrivateKey, "")
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := hostCertFile.Write(pem.Bytes); err != nil {
		return nil, nil, nil, err
	}

	sshCAPublic, err := ssh.NewPublicKey(caPublic)
	if err != nil {
		return nil, nil, nil, err
	}
	caFile, err := os.CreateTemp(tempDir, "ca-public-*")
	if err != nil {
		return nil, nil, nil, err
	}
	data := sshCAPublic.Marshal()
	if _, err := caFile.Write(data); err != nil {
		return nil, nil, nil, err
	}

	certFile, err := os.CreateTemp(tempDir, "cert-*")
	if err != nil {
		return nil, nil, nil, err
	}
	data = cert.Marshal()
	if _, err := certFile.Write(data); err != nil {
		return nil, nil, nil, err
	}
	return hostCertFile, certFile, caFile, nil
}

func generateRSAKey() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return key, &key.PublicKey, nil
}

func newCertificate(caSigner ssh.Signer, userPubKey ssh.PublicKey) (*ssh.Certificate, error) {
	cert := &ssh.Certificate{
		Key:             userPubKey,
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"username"},
		KeyId:           "user_cert",
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(365 * 24 * time.Hour).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{"permit-X11-forwarding": ""},
		},
	}

	err := cert.SignCert(rand.Reader, caSigner)
	if err != nil {
		return nil, fmt.Errorf("ошибка подписи сертификата: %v", err)
	}

	return cert, nil
}
