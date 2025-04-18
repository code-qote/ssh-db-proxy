package buffered

import (
	"io"
	"net"
	"time"
)

type CloserReadWriter interface {
	io.Reader
	io.Writer
	io.Closer
}

type Conn struct {
	conn       CloserReadWriter
	localAddr  net.Addr
	remoteAddr net.Addr
}

func NewConn(conn CloserReadWriter, localAddr, remoteAddr net.Addr) *Conn {
	c := &Conn{
		conn:       conn,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	return c
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.conn.Read(b)
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	n, err = c.conn.Write(b)
	return
}

func (c *Conn) Close() error {
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return nil
}
