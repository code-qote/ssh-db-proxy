package notifier

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/jackc/pgproto3/v2"
	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"ssh-db-proxy/internal/config"
	"ssh-db-proxy/internal/metadata"
)

const defaultCount = 100

type abacEvent struct {
	Time         time.Time         `json:"time"`
	Message      string            `json:"message"`
	MatchedRules []string          `json:"matched_rules"`
	Metadata     metadata.Metadata `json:"metadata"`
}

type Notifier struct {
	server *http.Server
	ch     chan any
	logger *zap.SugaredLogger
}

func New(config config.NotifierConfig, logger *zap.SugaredLogger) (*Notifier, error) {
	if !config.Enabled {
		return nil, fmt.Errorf("not enabled")
	}
	if logger == nil {
		logger = zap.NewNop().Sugar()
	}

	var tlsConfig *tls.Config

	if config.TLS.Enabled {
		caCert, err := os.ReadFile(config.TLS.ClientCAPath)
		if err != nil {
			return nil, fmt.Errorf("read client CA: %w", err)
		}

		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)

		serverCert, err := tls.LoadX509KeyPair(config.TLS.CertPath, config.TLS.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("load server cert and key: %w", err)
		}

		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			ClientCAs:    caCertPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
	}

	server := &http.Server{
		Addr:      fmt.Sprintf("%s:%d", config.Listen.Addr, config.Listen.Port),
		TLSConfig: tlsConfig,
	}
	n := &Notifier{
		server: server,
		ch:     make(chan any, config.Capacity),
		logger: logger,
	}

	server.Handler = n

	return n, nil
}

func (n *Notifier) Serve() error {
	if n == nil {
		return nil
	}
	if n.server.TLSConfig == nil {
		return n.server.ListenAndServe()
	}
	return n.server.ListenAndServeTLS("", "")
}

func (n *Notifier) Shutdown(ctx context.Context) error {
	if n == nil {
		return nil
	}
	return n.server.Shutdown(ctx)
}

func (n *Notifier) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	countString := r.URL.Query().Get("count")

	count, err := strconv.Atoi(countString)
	if err != nil {
		http.Error(w, "invalid count", http.StatusBadRequest)
		return
	}
	if count <= 0 {
		count = defaultCount
	}

	res := make([]any, 0, count)
	for i := 0; i < count; i++ {
		select {
		case item := <-n.ch:
			res = append(res, item)
		default:
			break
		}
	}

	data, err := json.Marshal(res)
	if err != nil {
		n.logger.Error(err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		n.logger.Error(err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
}

func (n *Notifier) OnConnectionAccept(connID, localAddress, remoteAddress string) {
	n.writeEvent("connection-accept", struct {
		ConnectionID  string `json:"connection_id"`
		LocalAddress  string `json:"local_address"`
		RemoteAddress string `json:"remote_address"`
	}{
		ConnectionID:  connID,
		LocalAddress:  localAddress,
		RemoteAddress: remoteAddress,
	})
}

func (n *Notifier) OnNotify(message string, matchedRules []string, data metadata.Metadata) {
	n.writeEvent("abac-rule", &abacEvent{
		Time:         time.Now(),
		Message:      message,
		MatchedRules: matchedRules,
		Metadata:     data,
	})
}

func (n *Notifier) OnAuthCertificate(cert *ssh.Certificate) {
	n.writeEvent("auth-certificate", struct {
		KeyID       string    `json:"key_id"`
		ValidAfter  time.Time `json:"valid_after"`
		ValidBefore time.Time `json:"valid_before"`
	}{
		KeyID:       cert.KeyId,
		ValidAfter:  time.Unix(int64(cert.ValidAfter), 0),
		ValidBefore: time.Unix(int64(cert.ValidBefore), 0),
	})
}

func (n *Notifier) OnDatabaseUsers(users []string, data metadata.Metadata) {
	n.writeEvent("database-users", struct {
		Users    []string          `json:"users"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Users:    users,
		Metadata: data,
	})
}

func (n *Notifier) OnDirectTCPIPRequest(data metadata.Metadata) {
	n.writeEvent("direct-tcpip-request", struct {
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Metadata: data,
	})
}

func (n *Notifier) OnQueryMessage(msg pgproto3.Query, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Query    `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnParseMessage(msg pgproto3.Parse, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Parse    `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnBindMessage(msg pgproto3.Bind, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Bind     `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnSyncMessage(msg pgproto3.Sync, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Sync     `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnExecuteMessage(msg pgproto3.Execute, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Execute  `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnDescribeMessage(msg pgproto3.Describe, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Describe `json:"message"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnTerminateMessage(msg pgproto3.Terminate, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.Terminate `json:"message"`
		Metadata metadata.Metadata  `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnStartupMessage(msg pgproto3.StartupMessage, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.StartupMessage `json:"message"`
		Metadata metadata.Metadata       `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnSSLRequest(msg pgproto3.SSLRequest, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.SSLRequest `json:"message"`
		Metadata metadata.Metadata   `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnGSSEncRequest(msg pgproto3.GSSEncRequest, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.GSSEncRequest `json:"message"`
		Metadata metadata.Metadata      `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnCancelRequest(msg pgproto3.CancelRequest, data metadata.Metadata) {
	n.writeEvent("query-message", struct {
		Message  pgproto3.CancelRequest `json:"message"`
		Metadata metadata.Metadata      `json:"metadata"`
	}{
		Message:  msg,
		Metadata: data,
	})
}

func (n *Notifier) OnDatabaseAuth(authErr error, data metadata.Metadata) {
	n.writeEvent("database-auth", struct {
		AuthenticationError error             `json:"authentication_error"`
		Metadata            metadata.Metadata `json:"metadata"`
	}{
		AuthenticationError: authErr,
		Metadata:            data,
	})
}

func (n *Notifier) OnConnectionClosed(err error, data metadata.Metadata) {
	n.writeEvent("connection-closed", struct {
		Error    error             `json:"error"`
		Metadata metadata.Metadata `json:"metadata"`
	}{
		Error:    err,
		Metadata: data,
	})
}

func (n *Notifier) writeEvent(eventName string, event any) {
	logger := n.logger.With("event", eventName)
	select {
	case n.ch <- event:
		return
	default:
		logger.Errorw("failed to send json message", "event", event)
	}
}
