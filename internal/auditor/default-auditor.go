package auditor

import (
	"encoding/json"
	"sync"

	"github.com/jackc/pgproto3/v2"
	"golang.org/x/crypto/ssh"
)

type DefaultRequestAudit struct {
	ID        string
	Username  string
	Database  string
	Hostname  string
	Port      uint32
	AuthError error
	Messages  []json.Marshaler
}

type DefaultConnectionAudit struct {
	ID            string
	LocalAddress  string
	RemoteAddress string
	Users         []string
	Requests      map[string]*DefaultRequestAudit
	IsClosed      bool
	Error         error
}

type DefaultAuditor struct {
	mu     sync.RWMutex
	audits map[string]*DefaultConnectionAudit

	onConnectionClosed func(*DefaultConnectionAudit)
}

func NewDefaultAuditor(onConnectionClosedCallback func(audit *DefaultConnectionAudit)) *DefaultAuditor {
	return &DefaultAuditor{audits: make(map[string]*DefaultConnectionAudit), onConnectionClosed: onConnectionClosedCallback}
}

func (a *DefaultAuditor) OnConnectionAccept(connID, localAddress, remoteAddress string) {
	a.mu.Lock()
	a.audits[connID] = &DefaultConnectionAudit{
		ID:            connID,
		LocalAddress:  localAddress,
		RemoteAddress: remoteAddress,
		Requests:      make(map[string]*DefaultRequestAudit),
	}
	a.mu.Unlock()
}

func (a *DefaultAuditor) OnAuthCertificate(cert *ssh.Certificate) {}

func (a *DefaultAuditor) OnDatabaseUsers(connID string, users []string) {
	a.mu.Lock()
	if connection, ok := a.audits[connID]; ok {
		connection.Users = users
	}
	a.mu.Unlock()
}

func (a *DefaultAuditor) OnDirectTCPIPRequest(connID, requestID string) {
	a.mu.Lock()
	if connection, ok := a.audits[connID]; ok {
		connection.Requests[requestID] = &DefaultRequestAudit{ID: requestID}
	}
	a.mu.Unlock()
}

func (a *DefaultAuditor) OnQueryMessage(connID, requestID string, msg pgproto3.Query) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnParseMessage(connID, requestID string, msg pgproto3.Parse) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnBindMessage(connID, requestID string, msg pgproto3.Bind) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnSyncMessage(connID, requestID string, msg pgproto3.Sync) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnExecuteMessage(connID, requestID string, msg pgproto3.Execute) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnDescribeMessage(connID, requestID string, msg pgproto3.Describe) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnTerminateMessage(connID, requestID string, msg pgproto3.Terminate) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnStartupMessage(connID, requestID string, msg pgproto3.StartupMessage) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnSSLRequest(connID, requestID string, msg pgproto3.SSLRequest) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnGSSEncRequest(connID, requestID string, msg pgproto3.GSSEncRequest) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnCancelRequest(connID, requestID string, msg pgproto3.CancelRequest) {
	a.appendMessage(connID, requestID, msg)
}

func (a *DefaultAuditor) OnDatabaseAuth(connID, requestID, username, hostname, database string, port uint32, authError error) {
	a.mu.Lock()
	if connection, ok := a.audits[connID]; ok {
		if request, ok := connection.Requests[requestID]; ok {
			request.Username = username
			request.Hostname = hostname
			request.Database = database
			request.Port = port
			request.AuthError = authError
		}
	}
	a.mu.Unlock()
}

func (a *DefaultAuditor) OnConnectionClosed(connID string, err error) {
	a.mu.Lock()
	if connection, ok := a.audits[connID]; ok {
		connection.IsClosed = true
		connection.Error = err
		a.onConnectionClosed(connection)
		delete(a.audits, connID)
	}
	a.mu.Unlock()
}

func (a *DefaultAuditor) appendMessage(connID, requestID string, msg json.Marshaler) {
	a.mu.Lock()
	if connection, ok := a.audits[connID]; ok {
		if request, ok := connection.Requests[requestID]; ok {
			request.Messages = append(request.Messages, msg)
		}
	}
	a.mu.Unlock()
}
