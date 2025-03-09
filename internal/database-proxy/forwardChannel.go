package database_proxy

import (
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

type forwardChannel struct {
	ch         ssh.Channel
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (f *forwardChannel) Read(b []byte) (n int, err error) {
	n, err = f.ch.Read(b)
	return
}

func (f *forwardChannel) Write(b []byte) (n int, err error) {
	n, err = f.ch.Write(b)
	return
}

func (f *forwardChannel) Close() error {
	return f.ch.Close()
}

func (f *forwardChannel) LocalAddr() net.Addr {
	return f.localAddr
}

func (f *forwardChannel) RemoteAddr() net.Addr {
	return f.remoteAddr
}

func (f *forwardChannel) SetDeadline(t time.Time) error {
	return nil
}

func (f *forwardChannel) SetReadDeadline(t time.Time) error {
	return nil
}

func (f *forwardChannel) SetWriteDeadline(t time.Time) error {
	return nil
}
