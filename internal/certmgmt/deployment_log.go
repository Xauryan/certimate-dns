package certmgmt

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
)

// Deployer SDK messages, responses and returned errors can contain credentials
// created during the request. The workflow journal only accepts diagnostics
// constructed from the fixed vocabulary below.
type deploymentLog struct{ target slog.Handler }

func newDeploymentLog(logger *slog.Logger) *deploymentLog {
	if logger == nil {
		return &deploymentLog{target: slog.DiscardHandler}
	}
	return &deploymentLog{target: logger.Handler()}
}

func deploymentError(err error, message string) error {
	switch {
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return fmt.Errorf("%s: connection timed out", message)
	}
	var status interface{ HTTPStatusCode() int }
	if errors.As(err, &status) {
		if code := status.HTTPStatusCode(); code >= 400 && code <= 599 {
			return fmt.Errorf("%s (HTTP %d)", message, code)
		}
	}
	return errors.New(message)
}

func (h *deploymentLog) Enabled(ctx context.Context, level slog.Level) bool {
	return h.target.Enabled(ctx, level)
}
func (h *deploymentLog) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *deploymentLog) WithGroup(string) slog.Handler      { return h }

func (h *deploymentLog) Handle(ctx context.Context, record slog.Record) error {
	message := record.Message
	switch message {
	case "ssl certificate uploaded", "ssl certificate replaced", "waiting for deployment task completion ...",
		"ssh connected", "ssl private key file uploaded", "ssl certificate file uploaded", "ssl certificate file saved", "ssl private key file saved":
		// These exact strings originate in the local adapters.
	default:
		if !strings.HasPrefix(message, "sdk request ") {
			return nil
		}
		message = "deployment provider SDK request"
	}
	safe := slog.NewRecord(record.Time, record.Level, message, record.PC)
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "count" && a.Value.Kind() == slog.KindInt64 && a.Value.Int64() >= 0 && a.Value.Int64() <= 100000 {
			safe.AddAttrs(a)
		}
		return true
	})
	return h.target.Handle(ctx, safe)
}
