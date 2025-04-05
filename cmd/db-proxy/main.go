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

	"ssh-db-proxy/internal/abac"
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

	conf := &config.Config{
		Host:               "localhost",
		Port:               "8080",
		NoClientAuth:       false,
		HostKeyPrivatePath: "/Users/niqote/ssh-db-proxy/dev/generated/ssh_host_rsa_key",
		UserCAPath:         "/Users/niqote/ssh-db-proxy/dev/generated/user_ca.pub",
		MITM: config.MITMConfig{
			ClientCAFilePath:     "/Users/niqote/ssh-db-proxy/dev/generated/tls/proxy-ca.pem",
			ClientPrivateKeyPath: "/Users/niqote/ssh-db-proxy/dev/generated/tls/proxy-ca.key",
			DatabaseCAPath:       "/Users/niqote/ssh-db-proxy/dev/generated/tls/ca.pem",
		},
		ABACRules: map[string]*abac.Rule{
			"night-time": {
				Conditions: []abac.Condition{
					&abac.TimeCondition{
						Location: "Europe/Moscow",
						Hour:     []abac.Interval{{From: 0, To: 9}, {From: 20, To: 23}},
					},
				},
				Actions: abac.Notify,
			},
			//"blocked-users": {
			//	Conditions: []abac.Condition{
			//		&abac.DatabaseUsernameCondition{Regexps: []string{"not_niqote"}},
			//	},
			//	Actions: abac.Notify | abac.NotPermit,
			//},
			"insert-into-table": {
				Conditions: []abac.Condition{
					&abac.QueryCondition{
						StatementType: "insert",
						TableRegexps:  []string{"table.*"},
						ColumnRegexps: []string{".*"},
					},
				},
				Actions: abac.Notify,
			},
			"delete-from-table": {
				Conditions: []abac.Condition{
					&abac.DatabaseUsernameCondition{Regexps: []string{"not_niqote"}},
					&abac.QueryCondition{
						StatementType: "delete",
						TableRegexps:  []string{"table.*"},
						ColumnRegexps: []string{".*"},
					},
				},
				Actions: abac.Notify | abac.NotPermit,
			},
		},
	}
	auditor := auditor.NewDefaultAuditor(func(audit *auditor.DefaultConnectionAudit) {
		b, err := json.Marshal(audit)
		if err == nil {
			os.WriteFile(fmt.Sprintf("/Users/niqote/ssh-db-proxy/dev/generated/audits/%s.json", audit.ID), b, 0644)
		}
	})
	proxy, err := database_proxy.NewDatabaseProxy(conf, auditor, logger)
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	logger.Infof("tunnel serves...")
	if err := proxy.Serve(ctx); err != nil {
		logger.Error(err)
	}
}
