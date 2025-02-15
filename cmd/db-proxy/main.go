package main

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"ssh-db-proxy/internal/config"
	"ssh-db-proxy/internal/tunnel"
)

func main() {
	conf := &config.TunnelConfig{
		Host:               "localhost",
		Port:               "8080",
		NoClientAuth:       true,
		HostKeyPrivatePath: "/Users/niqote/ssh-db-proxy/dev/hostkey",
	}
	tun, err := tunnel.NewTunnel(conf)
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Println(tun.Serve(ctx))
}
