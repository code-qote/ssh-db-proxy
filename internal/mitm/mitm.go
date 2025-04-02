package mitm

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime/pprof"
	"slices"
	"sync/atomic"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"ssh-db-proxy/internal/abac"
	"ssh-db-proxy/internal/auditor"
	"ssh-db-proxy/internal/certissuer"
	"ssh-db-proxy/internal/metadata"
)

const (
	txStatusIdle = 'I'
	notUseSSL    = 'N'
)

var (
	ErrUserPermissionDenied = errors.New("user permission denied")
	ErrDisconnectUser       = errors.New("disconnect user")
	ErrCancelledRequest     = errors.New("cancelled request")
	ErrTerminateMessage     = errors.New("terminate message")
)

type MITM struct {
	metadata metadata.Metadata

	users []string

	backend  *Backend
	frontend *Frontend

	serverHost string
	serverPort uint32

	certIssuer *certissuer.CertIssuer
	caCertPool *x509.CertPool

	auditor auditor.Auditor
	abac    *abac.ABAC

	logger *zap.SugaredLogger

	isHalfClosed atomic.Bool
}

func NewMITM(metadata metadata.Metadata, users []string, conn net.Conn, targetHost string, targetPort uint32, certIssuer *certissuer.CertIssuer, caCertPool *x509.CertPool, auditor auditor.Auditor, abac *abac.ABAC, logger *zap.SugaredLogger) (*MITM, error) {
	m := &MITM{
		metadata:   metadata,
		users:      users,
		backend:    &Backend{Conn: conn},
		serverHost: targetHost,
		serverPort: targetPort,
		certIssuer: certIssuer,
		caCertPool: caCertPool,
		auditor:    auditor,
		abac:       abac,
	}
	m.backend.Backend = pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
	return m, nil
}

func (m *MITM) Proxy(ctx context.Context) error {
	parameters, err := m.receiveStartupMessage()
	if err != nil {
		if errors.Is(err, ErrCancelledRequest) {
			return nil
		}
		return fmt.Errorf("receive startup message: %w", err)
	}
	if err := m.connectToDatabase(ctx, parameters); err != nil {
		if errors.Is(err, ErrUserPermissionDenied) || errors.Is(err, ErrDisconnectUser) {
			if err := m.backend.Send(&pgproto3.ErrorResponse{Code: "403", Message: "Permission Denied"}); err != nil {
				return fmt.Errorf("send permission denied message: %w", err)
			}
			if errors.Is(err, ErrDisconnectUser) {
				return err
			}
			return nil
		}
		return fmt.Errorf("connect to database: %w", err)
	}
	if err := m.prepareClient(); err != nil {
		return fmt.Errorf("prepare client: %w", err)
	}

	wg := errgroup.Group{}
	wg.Go(func() error {
		if err := m.proxyClientToServer(); err != nil {
			return fmt.Errorf("proxy client to server: %w", err)
		}
		return nil
	})
	wg.Go(func() error {
		if err := m.proxyServerToClient(); err != nil {
			return fmt.Errorf("proxy server to client: %w", err)
		}
		return nil
	})
	if err := wg.Wait(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Println(err)
	}
	return nil
}

func (m *MITM) prepareClient() error {
	if err := m.backend.Send(&pgproto3.AuthenticationOk{}); err != nil {
		return fmt.Errorf("sending auth ok message: %w", err)
	}
	if err := m.backend.Send(&pgproto3.BackendKeyData{ProcessID: m.frontend.ProcessID, SecretKey: m.frontend.SecretKey}); err != nil {
		return fmt.Errorf("sending backend key data: %w", err)
	}
	for name, value := range m.frontend.ParameterStatuses {
		if err := m.backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value}); err != nil {
			return fmt.Errorf("sending parameter status %s: %w", name, err)
		}
	}
	if err := m.backend.Send(&pgproto3.ReadyForQuery{TxStatus: txStatusIdle}); err != nil {
		return fmt.Errorf("sending ready for query: %w", err)
	}
	return nil
}

func (m *MITM) receiveStartupMessage() (map[string]string, error) {
	if err := m.backend.SetAuthType(pgproto3.AuthTypeMD5Password); err != nil {
		return nil, fmt.Errorf("set auth type: %w", err)
	}
	for {
		startupMessage, err := m.backend.ReceiveStartupMessage()
		if err != nil {
			return nil, fmt.Errorf("receive: %w", err)
		}
		switch msg := startupMessage.(type) {
		case *pgproto3.StartupMessage:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-startup-message-event"), func(ctx context.Context) {
				m.auditor.OnStartupMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
			})
			return msg.Parameters, nil
		case *pgproto3.SSLRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-ssl-request-event"), func(ctx context.Context) {
				m.auditor.OnSSLRequest(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
			})
			if _, err := m.backend.Write([]byte{notUseSSL}); err != nil {
				return nil, fmt.Errorf("write SSL request: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-gss-enc-request-event"), func(ctx context.Context) {
				m.auditor.OnGSSEncRequest(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
			})
			if _, err := m.backend.Write([]byte{notUseSSL}); err != nil {
				return nil, fmt.Errorf("write SSL request: %w", err)
			}
		case *pgproto3.CancelRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-cancel-request-event"), func(ctx context.Context) {
				m.auditor.OnCancelRequest(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
			})
			return nil, ErrCancelledRequest
		default:
			return nil, fmt.Errorf("unexpected StartupMessage type: %T", startupMessage)
		}
		continue
	}
}

func (m *MITM) proxyClientToServer() error {
	defer func() {
		m.frontend.Close()
		m.backend.Close()
	}()
	for {
		msg, err := m.backend.Receive()
		if err != nil {
			m.isHalfClosed.Store(true)
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return fmt.Errorf("receive from client: %w", err)
		}
		if err = m.handleMessage(msg); err != nil {
			if errors.Is(err, ErrTerminateMessage) {
				return nil
			}
			fmt.Println(err)
		}
		if err := m.frontend.Send(msg); err != nil {
			return fmt.Errorf("send to server: %w", err)
		}
	}
}

func (m *MITM) proxyServerToClient() error {
	defer func() {
		m.frontend.Close()
		m.backend.Close()
	}()
	for {
		msg, err := m.frontend.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) && m.isHalfClosed.Load() {
				return nil
			}
			return fmt.Errorf("receive from server: %w", err)
		}
		if isCloseMessage(msg) {
			return nil
		}
		if err := m.backend.Send(msg); err != nil {
			return fmt.Errorf("send to client: %w", err)
		}
	}
}

func isCloseMessage(msg pgproto3.BackendMessage) bool {
	_, ok := msg.(*pgproto3.CloseComplete)
	return ok
}

func (m *MITM) handleMessage(msg pgproto3.FrontendMessage) error {
	switch msg := msg.(type) {
	case *pgproto3.Query:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-query-message-event"), func(ctx context.Context) {
			m.auditor.OnQueryMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Parse:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-parse-message-event"), func(ctx context.Context) {
			m.auditor.OnParseMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Bind:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-parse-message-event"), func(ctx context.Context) {
			m.auditor.OnBindMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Sync:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-sync-message-event"), func(ctx context.Context) {
			m.auditor.OnSyncMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Execute:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-execute-message-event"), func(ctx context.Context) {
			m.auditor.OnExecuteMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Describe:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-describe-message-event"), func(ctx context.Context) {
			m.auditor.OnDescribeMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		return nil
	case *pgproto3.Terminate:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-terminate-message-event"), func(ctx context.Context) {
			m.auditor.OnTerminateMessage(m.metadata.ConnectionID, m.metadata.RequestID, msgV)
		})
		if err := m.frontend.Send(&pgproto3.Terminate{}); err != nil {
			return err
		}
		return ErrTerminateMessage
	default:
		return fmt.Errorf("unexpected Frontend message: %T", msg)
	}
}

func (m *MITM) connectToDatabase(ctx context.Context, frontendParameters map[string]string) error {
	if frontendParameters == nil {
		return fmt.Errorf("missing frontend parameters")
	}
	user, ok := frontendParameters["user"]
	if !ok {
		return fmt.Errorf("user not found in frontend parameters")
	}

	database, ok := frontendParameters["database"]
	if !ok {
		return fmt.Errorf("database not found in frontend parameters")
	}

	var authError error
	if !slices.Contains(m.users, user) {
		authError = fmt.Errorf("%w: forbidden username", ErrUserPermissionDenied)
	}
	go pprof.Do(context.Background(), pprof.Labels("name", "on-database-auth"), func(ctx context.Context) {
		m.auditor.OnDatabaseAuth(m.metadata.ConnectionID, m.metadata.RequestID, user, m.serverHost, database, m.serverPort, authError)
	})
	if authError != nil {
		return authError
	}

	actions, err := m.abac.Observe(m.metadata.StateID, abac.DatabaseNameEvent(database), abac.DatabaseUsernameEvent(user))
	if err == nil {
		if actions&abac.Notify > 0 {
			m.auditor.OnNotify(fmt.Sprintf("user %s connecting to %s", user, database), m.metadata)
		}
		if actions&abac.Disconnect > 0 {
			if actions&abac.Notify > 0 {
				m.auditor.OnNotify(fmt.Sprintf("user %s was not permitted to connect to %s and disconnected", user, database), m.metadata)
			}
			return fmt.Errorf("%w: forbidden username by administrator", ErrDisconnectUser)
		}
		if actions&abac.NotPermit > 0 || actions&abac.Disconnect > 0 {
			if actions&abac.Notify > 0 {
				m.auditor.OnNotify(fmt.Sprintf("user %s was not permitted to connect to %s", user, database), m.metadata)
			}
			return fmt.Errorf("%w: forbidden username by administrator", ErrUserPermissionDenied)
		}
	} else {
		m.logger.Errorw("failed to observe", "state-id", m.metadata.StateID, "err", err)
	}

	cert, err := m.certIssuer.Issue(user)
	if err != nil {
		return fmt.Errorf("issue certificate: %w", err)
	}

	config, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s:%d?sslmode=verify-full", m.serverHost, m.serverPort))
	if err != nil {
		return err
	}

	config.User = user
	config.Database = database
	config.RuntimeParams = frontendParameters

	config.TLSConfig = &tls.Config{
		ServerName:   m.serverHost,
		RootCAs:      m.caCertPool,
		ClientCAs:    m.caCertPool,
		Certificates: []tls.Certificate{cert},
	}

	conn, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return err
	}

	hijackedConn, err := conn.Hijack()
	if err != nil {
		return err
	}

	m.frontend = &Frontend{
		Conn:              hijackedConn.Conn,
		Frontend:          pgproto3.NewFrontend(pgproto3.NewChunkReader(hijackedConn.Conn), hijackedConn.Conn),
		ProcessID:         hijackedConn.PID,
		SecretKey:         hijackedConn.SecretKey,
		ParameterStatuses: hijackedConn.ParameterStatuses,
	}
	return nil
}
