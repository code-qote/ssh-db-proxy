package tunnel

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime/pprof"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"ssh-db-proxy/internal/mitm"
	wrapssh "ssh-db-proxy/internal/ssh"

	"ssh-db-proxy/internal/config"
)

var (
	ErrAuthError = errors.New("auth error")
)

type Tunnel struct {
	c         *config.TunnelConfig
	logger    *zap.SugaredLogger
	sshConfig *ssh.ServerConfig
}

func NewTunnel(config *config.TunnelConfig, logger *zap.SugaredLogger) (*Tunnel, error) {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

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
	return &Tunnel{c: config, sshConfig: sshConfig, logger: logger}, nil
}

func (t *Tunnel) Serve(ctx context.Context) error {
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
			go pprof.Do(ctx, pprof.Labels("name", "handle-connection"), func(ctx context.Context) {
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

func (t *Tunnel) acceptConnections(ctx context.Context, listener net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn)
	go pprof.Do(ctx, pprof.Labels("name", "accept-connections"), func(ctx context.Context) {
		for {
			conn, err := listener.Accept()
			if err != nil || ctx.Err() != nil {
				break
			}
			ch <- conn
		}
		close(ch)
	})
	return ch
}

func (t *Tunnel) handleConnection(ctx context.Context, conn net.Conn) error {
	sConn, newChans, reqs, err := ssh.NewServerConn(conn, t.sshConfig)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs) // todo

	var wg sync.WaitGroup
	for newChan := range newChans {
		newChan := newChan
		wg.Add(1)
		go pprof.Do(ctx, pprof.Labels("name", "handle-new-channel"), func(ctx context.Context) {
			err := t.handleChannel(ctx, newChan, conn.LocalAddr(), conn.RemoteAddr())
			if err != nil {
				t.logger.Errorf("handle channel: %v", err)
			}
		})
	}
	wg.Wait()
	return nil
}

func (t *Tunnel) handleChannel(ctx context.Context, newChan ssh.NewChannel, localAddr, remoteAddr net.Addr) error {
	if newChan.ChannelType() != "direct-tcpip" {
		if err := newChan.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			return fmt.Errorf("reject channel: %w", err)
		}
		return nil
	}

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

	m := mitm.NewMITM(&forwardChannel{
		ch:         ch,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}, p.HostToConnect, p.PortToConnect)

	return m.Proxy(ctx)
}
