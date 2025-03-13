package auditor

import (
	"github.com/jackc/pgproto3/v2"
	"golang.org/x/crypto/ssh"
)

type Auditor interface {
	OnConnectionAccept(connID, localAddress, remoteAddress string)
	OnAuthCertificate(cert *ssh.Certificate)
	OnDatabaseUsers(connID string, users []string)
	OnDirectTCPIPRequest(connID, requestID string)
	OnQueryMessage(connID, requestID string, msg pgproto3.Query)
	OnParseMessage(connID, requestID string, msg pgproto3.Parse)
	OnBindMessage(connID, requestID string, msg pgproto3.Bind)
	OnSyncMessage(connID, requestID string, msg pgproto3.Sync)
	OnExecuteMessage(connID, requestID string, msg pgproto3.Execute)
	OnDescribeMessage(connID, requestID string, msg pgproto3.Describe)
	OnTerminateMessage(connID, requestID string, msg pgproto3.Terminate)
	OnStartupMessage(connID, requestID string, msg pgproto3.StartupMessage)
	OnSSLRequest(connID, requestID string, msg pgproto3.SSLRequest)
	OnGSSEncRequest(connID, requestID string, msg pgproto3.GSSEncRequest)
	OnCancelRequest(connID, requestID string, msg pgproto3.CancelRequest)
	OnDatabaseAuth(connID, requestID, username, hostname, database string, port uint32, authError error)
	OnConnectionClosed(connID string, err error)
}
