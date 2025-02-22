package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"ssh-db-proxy/internal/config"
	"ssh-db-proxy/internal/tunnel"
)

func initLogger() *zap.SugaredLogger {
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderConfig),
		zapcore.AddSync(os.Stdout),
		zapcore.InfoLevel,
	)

	return zap.New(core).Sugar()
}

func main() {
	logger := initLogger()
	defer logger.Sync()
	zap.ReplaceGlobals(logger.Desugar())

	defer func() {
		if r := recover(); r != nil {
			zap.S().Errorf("recovered: %v", r)
		}
	}()

	conf := &config.TunnelConfig{
		Host:               "localhost",
		Port:               "8080",
		NoClientAuth:       false,
		HostKeyPrivatePath: "/Users/niqote/ssh-db-proxy/dev/generated/ssh_host_rsa_key",
		UserCAPath:         "/Users/niqote/ssh-db-proxy/dev/generated/user_ca.pub",
	}
	tun, err := tunnel.NewTunnel(conf, logger)
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Infof("tunnel serves...")
	if err := tun.Serve(ctx); err != nil {
		logger.Error(err)
	}
}
