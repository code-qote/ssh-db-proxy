package buffered

import (
	"bufio"
	"context"
	"io"
	"net"
	"runtime/pprof"
	"sync"
	"time"
)

const (
	bufferSize   = 128 * 1024 // 128kb
	flushTimeout = time.Millisecond
)

type CloserReadWriter interface {
	io.Reader
	io.Writer
	io.Closer
}

type Conn struct {
	wMu     sync.Mutex
	wBuffer *bufio.Writer

	rMu     sync.Mutex
	rBuffer *bufio.Reader

	ctx    context.Context
	cancel context.CancelFunc

	conn       CloserReadWriter
	localAddr  net.Addr
	remoteAddr net.Addr
}

func NewConn(conn CloserReadWriter, localAddr, remoteAddr net.Addr) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	f := &Conn{
		wBuffer:    bufio.NewWriterSize(conn, bufferSize),
		rBuffer:    bufio.NewReaderSize(conn, bufferSize),
		conn:       conn,
		ctx:        ctx,
		cancel:     cancel,
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
	}
	go pprof.Do(ctx, pprof.Labels("name", "forward-channel"), func(ctx context.Context) {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(flushTimeout):
				f.wMu.Lock()
				f.wBuffer.Flush()
				f.wMu.Unlock()
			}
		}
	})
	return f
}

func (c *Conn) Read(b []byte) (n int, err error) {
	n, err = c.rBuffer.Read(b)
	return
}

func (c *Conn) Write(b []byte) (n int, err error) {
	c.wMu.Lock()
	n, err = c.wBuffer.Write(b)
	c.wMu.Unlock()
	return
}

func (c *Conn) Close() error {
	c.wMu.Lock()
	defer c.wMu.Unlock()
	c.wBuffer.Flush()
	c.cancel()
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
