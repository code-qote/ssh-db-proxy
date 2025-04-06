package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"ssh-db-proxy/internal/auditor"
	"ssh-db-proxy/internal/config"
	"ssh-db-proxy/internal/database-proxy"
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

	auditor := auditor.NewDefaultAuditor(func(audit *auditor.DefaultConnectionAudit) {
		b, err := json.Marshal(audit)
		if err == nil {
			os.WriteFile(fmt.Sprintf("/Users/niqote/ssh-db-proxy/dev/generated/audits/%s.json", audit.ID), b, 0644)
		}
	})
	proxy, err := database_proxy.NewDatabaseProxy(conf, auditor, logger)
	if err != nil {
		logger.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Infof("tunnel serves...")
	if err := proxy.Serve(ctx); err != nil {
		logger.Error(err)
	}
}
