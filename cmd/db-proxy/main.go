package main

import (
	"context"
	"os"
	"os/signal"
	"runtime/pprof"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"ssh-db-proxy/internal/config"
	"ssh-db-proxy/internal/database-proxy"
	"ssh-db-proxy/internal/notifier"
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

	if len(os.Args) < 3 {
		logger.Fatalf("Usage: db-proxy --config <config_path>")
	}
	if os.Args[1] != "-c" && os.Args[1] != "--config" {
		logger.Fatalf("Usage: db-proxy --config <config_path>")
	}
	configPath := os.Args[2]

	conf, err := config.LoadConfig(configPath, nil)
	if err != nil {
		logger.Fatal(err)
	}

	notif, err := notifier.New(conf.Notifier, logger.With("name", "notifier"))
	if err != nil {
		logger.Fatal(err)
	}

	proxy, err := database_proxy.NewDatabaseProxy(conf, notif, logger)
	if err != nil {
		logger.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go pprof.Do(ctx, pprof.Labels("name", "notifier"), func(ctx context.Context) {
		logger.Error(notif.Serve())
	})

	logger.Infof("tunnel serves...")
	if err := proxy.Serve(ctx); err != nil {
		logger.Error(err)
	}
	logger.Fatal(notif.Shutdown(context.Background()))
}
