package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime/pprof"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sync/errgroup"

	wrapssh "ssh-db-proxy/internal/ssh"

	"ssh-db-proxy/internal/config"
)

type Tunnel struct {
	c         *config.TunnelConfig
	sshConfig *ssh.ServerConfig
}

func NewTunnel(config *config.TunnelConfig) (*Tunnel, error) {
	sshConfig := &ssh.ServerConfig{}
	if config.NoClientAuth {
		sshConfig.NoClientAuth = true
	} else {
		// todo
	}
	privateKeyBytes, err := os.ReadFile(config.HostKeyPrivatePath)
	if err != nil {
		return nil, fmt.Errorf("read private host key: %w", err)
	}
	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	sshConfig.AddHostKey(privateKey)
	return &Tunnel{c: config, sshConfig: sshConfig}, nil
}

func (t *Tunnel) Serve(ctx context.Context) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%s", t.c.Host, t.c.Port))
	if err != nil {
		return err
	}
	defer listener.Close()

	conns := t.acceptConnections(ctx, listener)
	wg := errgroup.Group{}

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case conn := <-conns:
			wg.Go(func() error { return t.handleConnection(ctx, conn) })
		}
	}
	return handleCloseError(wg.Wait())
}

func (t *Tunnel) acceptConnections(ctx context.Context, listener net.Listener) <-chan net.Conn {
	ch := make(chan net.Conn)
	go pprof.Do(ctx, pprof.Labels("name", "accept-connections"), func(ctx context.Context) {
		for {
			conn, err := listener.Accept()
			if err != nil || ctx.Err() != nil {
				break
			}
			ch <- conn
		}
		close(ch)
	})
	return ch
}

func (t *Tunnel) handleConnection(ctx context.Context, conn net.Conn) error {
	sConn, newChans, reqs, err := ssh.NewServerConn(conn, t.sshConfig)
	if err != nil {
		return fmt.Errorf("handshake failed: %w", err)
	}
	defer sConn.Close()

	go ssh.DiscardRequests(reqs) // todo

	wg := errgroup.Group{}
	for newChan := range newChans {
		newChan := newChan
		wg.Go(func() error {
			return t.handleChannel(ctx, newChan)
		})
	}
	return wg.Wait()
}

func (t *Tunnel) handleChannel(ctx context.Context, newChan ssh.NewChannel) error {
	if newChan.ChannelType() != "direct-tcpip" {
		if err := newChan.Reject(ssh.UnknownChannelType, "unsupported channel type"); err != nil {
			return fmt.Errorf("reject channel: %w", err)
		}
		return nil
	}

	ch, reqs, err := newChan.Accept()
	if err != nil {
		return fmt.Errorf("accept channel: %w", err)
	}
	defer ch.Close()

	var p wrapssh.DirectTCPIPPayload
	data := newChan.ExtraData()
	if err := ssh.Unmarshal(data, &p); err != nil {
		return fmt.Errorf("unmarshal payload: %w", err)
	}

	go ssh.DiscardRequests(reqs) // todo

	destination, err := net.Dial("tcp", fmt.Sprintf("%s:%d", p.HostToConnect, p.PortToConnect))
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer destination.Close()

	wg, ctx := errgroup.WithContext(ctx)
	wg.Go(func() error { return proxy(destination, ch) })
	wg.Go(func() error { return proxy(ch, destination) })
	<-ctx.Done()
	return errors.Join(handleCloseError(ch.Close()), handleCloseError(destination.Close()), wg.Wait())
}

func proxy(dest io.Writer, src io.Reader) error {
	const bufferSize = 1000
	buffer := make([]byte, bufferSize)
	for {
		n, err := src.Read(buffer)
		if n > 0 {
			if _, err := dest.Write(buffer[:n]); err != nil {
				if errors.Is(err, io.EOF) {
					return nil
				}
				return fmt.Errorf("write to dest: %w", err)
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read from src: %w", err)
		}
	}
}

func handleCloseError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "use of closed network connection") {
		return nil
	}
	return err
}
