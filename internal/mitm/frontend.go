package mitm

import (
	"net"

	"github.com/jackc/pgproto3/v2"
)

type Frontend struct {
	net.Conn
	*pgproto3.Frontend
	ProcessID         uint32
	SecretKey         uint32
	ParameterStatuses map[string]string
}

type Backend struct {
	net.Conn
	*pgproto3.Backend
}
