package database_proxy

import (
	"context"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"ssh-db-proxy/internal/auditor"
	"ssh-db-proxy/internal/certissuer"
	"ssh-db-proxy/internal/mitm"
	wrapssh "ssh-db-proxy/internal/ssh"

	"ssh-db-proxy/internal/config"
)

var (
	ErrAuthError = errors.New("auth error")
)

type DatabaseProxy struct {
	c         *config.Config
	logger    *zap.SugaredLogger
	sshConfig *ssh.ServerConfig

	auditor auditor.Auditor

	certIssuer         *certissuer.CertIssuer
	databaseCACertPool *x509.CertPool
}

type ConnWithId struct {
	ID   string
	Conn net.Conn
}

func NewDatabaseProxy(config *config.Config, auditor auditor.Auditor, logger *zap.SugaredLogger) (*DatabaseProxy, error) {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	mitmConfig := config.MITMConfig
	certIssuer, err := certissuer.NewCertIssuer(mitmConfig.ClientCAFilePath, mitmConfig.ClientPrivateKeyPath)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	pems, err := os.ReadFile(mitmConfig.DatabaseCAPath)
	if err != nil {
		return nil, err
	}
	certPool.AppendCertsFromPEM(pems)

	sshConfig := &ssh.ServerConfig{}
	if config.NoClientAuth {
		sshConfig.NoClientAuth = true
	} else {
		userCABytes, err := os.ReadFile(config.UserCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read user CA bundle: %w", err)
		}
		userCA, _, _, _, err := ssh.ParseAuthorizedKey(userCABytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse user CA bundle: %w", err)
		}
		sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			switch cert := key.(type) {
			case *ssh.Certificate:
				go pprof.Do(context.Background(), pprof.Labels("name", "on-auth-certificate-event"), func(ctx context.Context) {
					auditor.OnAuthCertificate(cert)
				})
				validAfter := time.Unix(int64(cert.ValidAfter), 0)
				validBefore := time.Unix(int64(cert.ValidBefore), 0)
				logger.Infow("tries to auth",
					"key-id", cert.KeyId,
					"valid-after", validAfter,
					"valid-before", validBefore,
				)
				if validAfter.After(time.Now()) {
					return nil, fmt.Errorf("%w: certificate is not active", ErrAuthError)
				}
				if validBefore.Before(time.Now()) {
					return nil, fmt.Errorf("%w: certificate has expired", ErrAuthError)
				}
				if subtle.ConstantTimeCompare(userCA.Marshal(), cert.SignatureKey.Marshal()) == 0 {
					return nil, fmt.Errorf("%w: invalid signature", ErrAuthError)
				}
				if len(cert.ValidPrincipals) == 0 {
					return nil, fmt.Errorf("%w: no valid principals", ErrAuthError)
				}
				cert.Permissions.Extensions["users"] = strings.Join(cert.ValidPrincipals, ",")
				return &cert.Permissions, nil
			default:
				return nil, fmt.Errorf("received non-certificate key type: %T", key)
			}
		}
	}
	privateKeyBytes, err := os.ReadFile(config.HostKeyPrivatePath)
	if err != nil {
		return nil, fmt.Errorf("read private host key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	sshConfig.AddHostKey(privateKey)
	return &DatabaseProxy{
		c:                  config,
		sshConfig:          sshConfig,
		logger:             logger,
		auditor:            auditor,
		certIssuer:         certIssuer,
		databaseCACertPool: certPool}, nil
}

func (t *DatabaseProxy) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", t.c.Host, t.c.Port))
	if err != nil {
		return err
	}
	defer listener.Close()

	conns := t.acceptConnections(ctx, listener)
	var wg sync.WaitGroup

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case conn := <-conns:
			wg.Add(1)
			go pprof.Do(ctx, pprof.Labels("name", "handle-connection"), func(ctx context.Context) {
				defer wg.Done()
				ctx = context.Background()
				if err := t.handleConnection(ctx, conn); err != nil {
					if errors.Is(err, ErrAuthError) {
						t.logger.Info(err)
					}
					t.logger.Error(err)
				}
			})
		}
	}
	wg.Wait()
	return nil
}

func (t *DatabaseProxy) acceptConnections(ctx context.Context, listener net.Listener) <-chan ConnWithId {
	ch := make(chan ConnWithId)
	go pprof.Do(ctx, pprof.Labels("name", "accept-connections"), func(ctx context.Context) {
		for {
			conn, err := listener.Accept()
			if err != nil || ctx.Err() != nil {
				break
			}
			id := uuid.New().String()
			t.logger.Infow("accepted connection", "id", id)
			connWithId := ConnWithId{
				ID:   id,
				Conn: conn,
			}
			go pprof.Do(ctx, pprof.Labels("name", "on-connection-accept-event"), func(ctx context.Context) {
				t.auditor.OnConnectionAccept(id, conn.LocalAddr().String(), conn.RemoteAddr().String())
			})
			ch <- connWithId
		}
		close(ch)
	})
	return ch
}

func (t *DatabaseProxy) handleConnection(ctx context.Context, conn ConnWithId) error {
	sConn, newChans, reqs, err := ssh.NewServerConn(conn.Conn, t.sshConfig)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	defer func() {
		t.logger.Infow("closed connection", "id", conn.ID)
		go pprof.Do(ctx, pprof.Labels("name", "on-closed-connection-event"), func(ctx context.Context) {
			err := sConn.Close()
			if strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			t.auditor.OnConnectionClosed(conn.ID, err)
		})
	}()

	databaseUsersString, ok := sConn.Permissions.Extensions["users"]
	if !ok {
		return fmt.Errorf("missing user permissions")
	}
	databaseUsers := strings.Split(databaseUsersString, ",")
	go pprof.Do(ctx, pprof.Labels("name", "on-database-users-event"), func(ctx context.Context) {
		t.auditor.OnDatabaseUsers(conn.ID, databaseUsers)
	})

	go ssh.DiscardRequests(reqs) // todo

	var wg sync.WaitGroup
	for newChan := range newChans {
		newChan := newChan
		wg.Add(1)
		go pprof.Do(ctx, pprof.Labels("name", "handle-new-channel"), func(ctx context.Context) {
			defer wg.Done()
			err := t.handleChannel(ctx, conn.ID, databaseUsers, newChan, conn.Conn.LocalAddr(), conn.Conn.RemoteAddr())
			if err != nil {
				t.logger.Errorf("handle channel: %v", err)
			}
		})
	}
	wg.Wait()
	return nil
}

func (t *DatabaseProxy) handleChannel(ctx context.Context, connID string, databaseUsers []string, newChan ssh.NewChannel, localAddr, remoteAddr net.Addr) error {
	if newChan.ChannelType() != "direct-tcpip" {
		if err := newChan.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			return fmt.Errorf("reject channel: %w", err)
		}
		return nil
	}
	requestID := uuid.New().String()
	t.logger.Infow("accepted new request", "id", requestID)
	defer func() {
		t.logger.Infow("finished request", "id", requestID)
	}()
	go pprof.Do(ctx, pprof.Labels("name", "on-direct-tcpip-request-event"), func(ctx context.Context) {
		t.auditor.OnDirectTCPIPRequest(connID, requestID)
	})

	ch, reqs, err := newChan.Accept()
	if err != nil {
		return fmt.Errorf("accept channel: %w", err)
	}
	defer ch.Close()

	var p wrapssh.DirectTCPIPPayload
	data := newChan.ExtraData()
	if err := ssh.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	go ssh.DiscardRequests(reqs) // todo

	m, err := mitm.NewMITM(connID, requestID, databaseUsers, &forwardChannel{
		ch:         ch,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, p.HostToConnect, p.PortToConnect, t.certIssuer, t.databaseCACertPool, t.auditor)
	if err != nil {
		return fmt.Errorf("create MITM: %w", err)
	}

	return m.Proxy(ctx)
}
