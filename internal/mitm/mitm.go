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
	"strings"
	"sync/atomic"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"

	"ssh-db-proxy/internal/abac"
	"ssh-db-proxy/internal/certissuer"
	"ssh-db-proxy/internal/metadata"
	"ssh-db-proxy/internal/notifier"
	"ssh-db-proxy/internal/sql"
)

const (
	txStatusIdle = 'I'
	notUseSSL    = 'N'

	bufferSize = 512 * 1024 // 512kb
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

	notifier *notifier.Notifier
	abac     *abac.ABAC

	logger *zap.SugaredLogger

	isHalfClosed atomic.Bool
}

func NewMITM(metadata metadata.Metadata, users []string, conn net.Conn, targetHost string, targetPort uint32, certIssuer *certissuer.CertIssuer, caCertPool *x509.CertPool, notifier *notifier.Notifier, abac *abac.ABAC, logger *zap.SugaredLogger) (*MITM, error) {
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}
	m := &MITM{
		metadata:   metadata,
		users:      users,
		backend:    &Backend{Conn: conn},
		serverHost: targetHost,
		serverPort: targetPort,
		certIssuer: certIssuer,
		caCertPool: caCertPool,
		notifier:   notifier,
		abac:       abac,
		logger:     logger,
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

	var (
		disconnect bool
		wg         errgroup.Group
	)
	wg.Go(func() error {
		if err := m.proxyClientToServer(); err != nil {
			if errors.Is(err, ErrDisconnectUser) {
				disconnect = true
			}
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
	err = wg.Wait()
	if err != nil && !errors.Is(err, io.EOF) {
		m.logger.Error(err)
	}
	if disconnect {
		return ErrDisconnectUser
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
				m.notifier.OnStartupMessage(msgV, m.metadata)
			})
			return msg.Parameters, nil
		case *pgproto3.SSLRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-ssl-request-event"), func(ctx context.Context) {
				m.notifier.OnSSLRequest(msgV, m.metadata)
			})
			if _, err := m.backend.Write([]byte{notUseSSL}); err != nil {
				return nil, fmt.Errorf("write SSL request: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-gss-enc-request-event"), func(ctx context.Context) {
				m.notifier.OnGSSEncRequest(msgV, m.metadata)
			})
			if _, err := m.backend.Write([]byte{notUseSSL}); err != nil {
				return nil, fmt.Errorf("write SSL request: %w", err)
			}
		case *pgproto3.CancelRequest:
			msgV := *msg
			go pprof.Do(context.Background(), pprof.Labels("name", "on-cancel-request-event"), func(ctx context.Context) {
				m.notifier.OnCancelRequest(msgV, m.metadata)
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
				if err := m.frontend.Send(&pgproto3.Terminate{}); err != nil {
					return err
				}
				return nil
			}
			if errors.Is(err, ErrUserPermissionDenied) {
				if err := m.backend.Send(&pgproto3.ErrorResponse{Code: "403", Message: "Query is not permitted by administrator"}); err != nil {
					return err
				}
				if err := m.backend.Send(&pgproto3.ReadyForQuery{TxStatus: txStatusIdle}); err != nil {
					return err
				}
				continue
			}
			if errors.Is(err, ErrDisconnectUser) {
				m.isHalfClosed.Store(true)
				if err := m.frontend.Send(&pgproto3.Terminate{}); err != nil {
					return err
				}
				if err := m.backend.Send(&pgproto3.ErrorResponse{Code: "403", Message: "Query is not permitted by administrator"}); err != nil {
					return err
				}
				return ErrDisconnectUser
			}
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

	b := make([]byte, bufferSize)
	for {
		n, err := m.frontend.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) || strings.Contains(err.Error(), "use of closed") || (errors.Is(err, io.ErrUnexpectedEOF) && m.isHalfClosed.Load()) {
				return nil
			}
			return fmt.Errorf("receive from server: %w", err)
		}
		if _, err := m.backend.Write(b[:n]); err != nil {
			return fmt.Errorf("send to client: %w", err)
		}
	}
}

func (m *MITM) handleMessage(msg pgproto3.FrontendMessage) error {
	switch msg := msg.(type) {
	case *pgproto3.Query:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-query-message-event"), func(ctx context.Context) {
			m.notifier.OnQueryMessage(msgV, m.metadata)
		})
		return m.onQuery(msgV.String)
	case *pgproto3.Parse:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-parse-message-event"), func(ctx context.Context) {
			m.notifier.OnParseMessage(msgV, m.metadata)
		})
		return m.onQuery(msgV.Query)
	case *pgproto3.Bind:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-parse-message-event"), func(ctx context.Context) {
			m.notifier.OnBindMessage(msgV, m.metadata)
		})
		return nil
	case *pgproto3.Sync:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-sync-message-event"), func(ctx context.Context) {
			m.notifier.OnSyncMessage(msgV, m.metadata)
		})
		return nil
	case *pgproto3.Execute:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-execute-message-event"), func(ctx context.Context) {
			m.notifier.OnExecuteMessage(msgV, m.metadata)
		})
		return nil
	case *pgproto3.Describe:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-describe-message-event"), func(ctx context.Context) {
			m.notifier.OnDescribeMessage(msgV, m.metadata)
		})
		return nil
	case *pgproto3.Terminate:
		msgV := *msg
		go pprof.Do(context.Background(), pprof.Labels("name", "on-terminate-message-event"), func(ctx context.Context) {
			m.notifier.OnTerminateMessage(msgV, m.metadata)
		})
		return ErrTerminateMessage
	default:
		return fmt.Errorf("unexpected Frontend message: %T", msg)
	}
}

func (m *MITM) onQuery(query string) error {
	queryStatements, err := sql.ExtractQueryStatements(query)
	if err != nil {
		m.logger.Errorf("extract query statements: %s", err)
		return nil
	}
	stateID := m.abac.NewStateFrom(m.metadata.StateID, nil)
	defer m.abac.DeleteState(stateID)

	actions, rules, err := m.abac.Observe(stateID, abac.QueryStatementsEvent(queryStatements))
	if err != nil {
		m.logger.Errorf("observe query statements: %s", err)
	}
	var data metadata.Metadata
	if actions > 0 {
		data = m.metadata.Copy()
		for _, statement := range queryStatements {
			data.QueryStatements = append(data.QueryStatements, metadata.QueryStatement{
				StatementType: sql.StringByStatementType[statement.Type],
				Table:         statement.Table,
				Column:        statement.Column,
			})
		}
		data.Query = query
	}
	if actions&abac.Notify > 0 {
		m.notifier.OnNotify("query statements observed", rules, data)
	}
	if actions&abac.Disconnect > 0 {
		if err := m.frontend.Send(&pgproto3.Terminate{}); err != nil {
			return err
		}
		if actions&abac.Notify > 0 {
			m.notifier.OnNotify("user was disconnected from database because of the query", rules, data)
		}
		return ErrDisconnectUser
	}
	if actions&abac.NotPermit > 0 {
		if actions&abac.Notify > 0 {
			m.notifier.OnNotify("query was not permitted", rules, data)
		}
		return ErrUserPermissionDenied
	}
	return nil
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
		m.notifier.OnDatabaseAuth(authError, m.metadata)
	})
	if authError != nil {
		return authError
	}

	if err := m.observeConnection(user, database); err != nil {
		return err
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

	m.metadata.DatabaseName = database
	m.metadata.DatabaseUsername = user

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

func (m *MITM) observeConnection(user, database string) error {
	actions, rules, err := m.abac.Observe(
		m.metadata.StateID,
		abac.DatabaseNameEvent(database),
		abac.DatabaseUsernameEvent(user),
	)
	if err == nil {
		if actions&abac.Notify > 0 {
			m.notifier.OnNotify(fmt.Sprintf("user %s connecting to %s", user, database), rules, m.metadata)
		}
		if actions&abac.Disconnect > 0 {
			if actions&abac.Notify > 0 {
				m.notifier.OnNotify(fmt.Sprintf("user %s was not permitted to connect to %s and disconnected",
					user, database), rules, m.metadata)
			}
			return fmt.Errorf("%w: forbidden username by administrator", ErrDisconnectUser)
		}
		if actions&abac.NotPermit > 0 {
			if actions&abac.Notify > 0 {
				m.notifier.OnNotify(fmt.Sprintf("user %s was not permitted to connect to %s",
					user, database), rules, m.metadata)
			}
			return fmt.Errorf("%w: forbidden username by administrator", ErrUserPermissionDenied)
		}
	} else {
		m.logger.Errorw("failed to observe", "state-id", m.metadata.StateID, "err", err)
	}
	return nil
}
