package mitm

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/jackc/pgconn"
	"github.com/jackc/pgproto3/v2"
	"golang.org/x/sync/errgroup"

	"ssh-db-proxy/internal/recorder"
)

const (
	txStatusIdle = 'I'
	notUseSSL    = 'N'
)

type MITM struct {
	backend  *Backend
	frontend *Frontend

	serverHost string
	serverPort uint32

	isHalfClosed atomic.Bool
}

func NewMITM(conn net.Conn, targetHost string, targetPort uint32) *MITM {
	m := &MITM{
		backend:    &Backend{Conn: conn},
		serverHost: targetHost,
		serverPort: targetPort,
	}
	m.backend.Backend = pgproto3.NewBackend(pgproto3.NewChunkReader(conn), conn)
	return m
}

func (m *MITM) Proxy(ctx context.Context) error {
	parameters, err := m.receiveStartupMessage()
	if err != nil {
		return fmt.Errorf("receive startup message: %w", err)
	}
	if err := m.connectToDatabase(ctx, parameters); err != nil {
		return fmt.Errorf("connect to database: %w", err)
	}
	if err := m.prepareClient(); err != nil {
		return fmt.Errorf("prepare client: %w", err)
	}

	r := &recorder.Recorder{}
	wg := errgroup.Group{}
	wg.Go(func() error {
		if err := m.proxyClientToServer(r); err != nil {
			return fmt.Errorf("proxy client to server: %w", err)
		}
		return nil
	})
	wg.Go(func() error {
		if err := m.proxyServerToClient(r); err != nil {
			return fmt.Errorf("proxy server to client: %w", err)
		}
		return nil
	})
	if err := wg.Wait(); err != nil && !errors.Is(err, io.EOF) {
		fmt.Println(err)
	}
	r.Save()
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
			return msg.Parameters, nil
		case *pgproto3.SSLRequest:
			if _, err := m.backend.Write([]byte{notUseSSL}); err != nil {
				return nil, fmt.Errorf("write SSL request: %w", err)
			}
		case *pgproto3.GSSEncRequest:
			return nil, fmt.Errorf("GSS Enc not implemented")
		case *pgproto3.CancelRequest:
			return nil, fmt.Errorf("Cancel not implemented")
		default:
			return nil, fmt.Errorf("unexpected StartupMessage type: %T", startupMessage)
		}
		continue
	}
}

func (m *MITM) proxyClientToServer(r *recorder.Recorder) error {
	for {
		msg, err := m.backend.Receive()
		if err != nil {
			fmt.Println("from client", err)
			return fmt.Errorf("receive from client: %w", err)
		}
		r.WriteFrontendMessage(msg)
		if isTerminateMessage(msg) {
			m.isHalfClosed.Store(true)
			if err := m.frontend.Send(&pgproto3.Terminate{}); err != nil {
				return err
			}
			return nil
		}
		if err = m.handleMessage(msg); err != nil {
			fmt.Println(err)
		}
		if err := m.frontend.Send(msg); err != nil {
			return fmt.Errorf("send to server: %w", err)
		}
	}
}

func isTerminateMessage(msg pgproto3.FrontendMessage) bool {
	_, ok := msg.(*pgproto3.Terminate)
	return ok
}

func (m *MITM) proxyServerToClient(r *recorder.Recorder) error {
	for {
		msg, err := m.frontend.Receive()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) && m.isHalfClosed.Load() {
				return nil
			}
			return fmt.Errorf("receive from server: %w", err)
		}
		r.WriteBackendMessage(msg)
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
	case *pgproto3.Parse:
		fmt.Println(msg.Name, msg.Query, msg.ParameterOIDs)
		return nil
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

	config, err := pgconn.ParseConfig(fmt.Sprintf("postgres://%s:%d?sslrootcert=/Users/niqote/ssh-db-proxy/dev/generated/tls/ca.pem&sslmode=verify-full", m.serverHost, m.serverPort))
	if err != nil {
		return err
	}

	config.User = user
	config.Database = database
	config.Password = "pgpassword"
	config.RuntimeParams = frontendParameters

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
