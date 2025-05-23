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

	"ssh-db-proxy/internal/abac"
	"ssh-db-proxy/internal/buffered"
	"ssh-db-proxy/internal/certissuer"
	"ssh-db-proxy/internal/metadata"
	"ssh-db-proxy/internal/mitm"
	"ssh-db-proxy/internal/notifier"
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

	notifier *notifier.Notifier
	abac     *abac.ABAC

	certIssuer         *certissuer.CertIssuer
	databaseCACertPool *x509.CertPool
}

type ConnWithMetadata struct {
	Conn     net.Conn
	Metadata metadata.Metadata
}

func NewDatabaseProxy(config *config.Config, auditor *notifier.Notifier, logger *zap.SugaredLogger) (*DatabaseProxy, error) {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	mitmConfig := config.MITM
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

	a, err := abac.New(*config.ABACRules.Load())
	if err != nil {
		return nil, fmt.Errorf("create abac: %w", err)
	}

	return &DatabaseProxy{
		c:                  config,
		sshConfig:          sshConfig,
		logger:             logger,
		notifier:           auditor,
		abac:               a,
		certIssuer:         certIssuer,
		databaseCACertPool: certPool}, nil
}

func (proxy *DatabaseProxy) Serve(ctx context.Context) error {
	if proxy.c.HotReload.Enabled {
		proxy.logger.Infof("hot reload is enabled")
		go pprof.Do(ctx, pprof.Labels("name", "config-hot-reloading"), func(ctx context.Context) {
			proxy.hotReloadConfig(ctx, proxy.c, proxy.logger.With("name", "config-hot-reloading"))
		})
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", proxy.c.Host, proxy.c.Port))
	if err != nil {
		return err
	}
	defer listener.Close()

	conns := proxy.acceptConnections(ctx, listener)
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
				if err := proxy.handleConnection(ctx, conn); err != nil {
					if errors.Is(err, ErrAuthError) {
						proxy.logger.Info(err)
					}
					proxy.logger.Error(err)
				}
			})
		}
	}
	wg.Wait()
	return nil
}

func (proxy *DatabaseProxy) acceptConnections(ctx context.Context, listener net.Listener) <-chan ConnWithMetadata {
	ch := make(chan ConnWithMetadata)
	go pprof.Do(ctx, pprof.Labels("name", "accept-connections"), func(ctx context.Context) {
		for {
			conn, err := listener.Accept()
			if err != nil || ctx.Err() != nil {
				break
			}
			id := uuid.New().String()
			proxy.logger.Infow("accepted connection", "id", id)
			connWithMetadata := ConnWithMetadata{
				Conn: conn,
				Metadata: metadata.Metadata{
					ConnectionID: id,
					RemoteAddr:   conn.RemoteAddr().String(),
				},
			}
			connWithMetadata.Metadata.StateID = proxy.abac.NewState(func() {
				if err := proxy.observeConnection(&connWithMetadata); err != nil {
					if errors.Is(err, mitm.ErrDisconnectUser) {
						connWithMetadata.Conn.Close()
					}
				}
			})
			if err := proxy.observeConnection(&connWithMetadata); err != nil {
				if errors.Is(err, mitm.ErrDisconnectUser) {
					connWithMetadata.Conn.Close()
				}
				continue
			}
			go pprof.Do(ctx, pprof.Labels("name", "on-connection-accept-event"), func(ctx context.Context) {
				proxy.notifier.OnConnectionAccept(id, conn.LocalAddr().String(), conn.RemoteAddr().String())
			})
			ch <- connWithMetadata
		}
		close(ch)
	})
	return ch
}

func (proxy *DatabaseProxy) observeConnection(connWithMetadata *ConnWithMetadata) error {
	actions, rules, err := proxy.abac.Observe(connWithMetadata.Metadata.StateID, abac.IPEvent(connWithMetadata.Conn.RemoteAddr().String()), abac.TimeEvent(time.Now()))
	if err == nil {
		if actions&abac.Notify > 0 {
			proxy.notifier.OnNotify("got-connection", rules, connWithMetadata.Metadata)
		}
		if actions&abac.NotPermit > 0 || actions&abac.Disconnect > 0 {
			if actions&abac.Notify > 0 {
				proxy.notifier.OnNotify("not-permitted-connection", rules, connWithMetadata.Metadata)
			}
			if err := connWithMetadata.Conn.Close(); err != nil {
				proxy.logger.Errorw("failed to close connection", "id", connWithMetadata.Metadata.ConnectionID, "err", err)
			}
			return mitm.ErrDisconnectUser
		}
	} else {
		proxy.logger.Errorw("failed to observe", "state-id", connWithMetadata.Metadata.StateID, "err", err)
	}
	return nil
}

func (proxy *DatabaseProxy) handleConnection(ctx context.Context, conn ConnWithMetadata) error {
	sConn, newChans, reqs, err := ssh.NewServerConn(conn.Conn, proxy.sshConfig)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	defer func() {
		proxy.logger.Infow("closed connection", "id", conn.Metadata.ConnectionID)
		go pprof.Do(ctx, pprof.Labels("name", "on-closed-connection-event"), func(ctx context.Context) {
			err := sConn.Close()
			if strings.Contains(err.Error(), "use of closed network connection") {
				err = nil
			}
			proxy.notifier.OnConnectionClosed(err, conn.Metadata)
			proxy.abac.DeleteState(conn.Metadata.StateID)
		})
	}()

	databaseUsersString, ok := sConn.Permissions.Extensions["users"]
	if !ok {
		return fmt.Errorf("missing user permissions")
	}
	databaseUsers := strings.Split(databaseUsersString, ",")
	go pprof.Do(ctx, pprof.Labels("name", "on-database-users-event"), func(ctx context.Context) {
		proxy.notifier.OnDatabaseUsers(databaseUsers, conn.Metadata)
	})

	go ssh.DiscardRequests(reqs)

	var wg sync.WaitGroup
	for newChan := range newChans {
		newChan := newChan
		wg.Add(1)
		go pprof.Do(ctx, pprof.Labels("name", "handle-new-channel"), func(ctx context.Context) {
			defer wg.Done()
			err := proxy.handleChannel(ctx, conn.Metadata, databaseUsers, newChan, conn.Conn.LocalAddr(), conn.Conn.RemoteAddr())
			if err != nil {
				if errors.Is(err, mitm.ErrDisconnectUser) {
					if err := conn.Conn.Close(); err != nil {
						proxy.logger.Errorw("failed to close connection", "id", conn.Metadata.ConnectionID, "err", err)
						return
					}
				}
				proxy.logger.Errorf("handle channel: %v", err)
			}
		})
	}
	wg.Wait()
	return nil
}

func (proxy *DatabaseProxy) handleChannel(ctx context.Context, metadata metadata.Metadata, databaseUsers []string, newChan ssh.NewChannel, localAddr, remoteAddr net.Addr) error {
	if newChan.ChannelType() != "direct-tcpip" {
		if err := newChan.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			return fmt.Errorf("reject channel: %w", err)
		}
		return nil
	}
	requestID := uuid.New().String()
	metadata.RequestID = requestID
	proxy.logger.Infow("accepted new request", "id", requestID)
	defer func() {
		proxy.logger.Infow("finished request", "id", requestID)
	}()
	go pprof.Do(ctx, pprof.Labels("name", "on-direct-tcpip-request-event"), func(ctx context.Context) {
		proxy.notifier.OnDirectTCPIPRequest(metadata)
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

	go ssh.DiscardRequests(reqs)

	m, err := mitm.NewMITM(metadata, databaseUsers, buffered.NewConn(ch, localAddr, remoteAddr), p.HostToConnect, p.PortToConnect, proxy.certIssuer, proxy.databaseCACertPool, proxy.notifier, proxy.abac, proxy.logger.With("name", "mitm", "connection-id", metadata.ConnectionID, "request-id", metadata.RequestID))
	if err != nil {
		return fmt.Errorf("create MITM: %w", err)
	}

	return m.Proxy(ctx)
}

func (proxy *DatabaseProxy) hotReloadConfig(ctx context.Context, conf *config.Config, logger *zap.SugaredLogger) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(conf.HotReload.Period):
			newConfig, err := config.LoadConfig(conf.ConfigPath, conf)
			if err != nil {
				if !errors.Is(err, config.ErrConfigNotChanged) {
					logger.Errorf("hot reload config from file %s: %s", conf.ConfigPath, err)
				}
				continue
			}
			conf = newConfig
			if err := proxy.abac.Update(*conf.ABACRules.Load()); err != nil {
				logger.Errorf("update ABAC: %s", err)
				continue
			}
			proxy.c = conf
			logger.Infof("hot reloaded config from file %s", conf.ConfigPath)
		}
	}
}
