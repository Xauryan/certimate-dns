package certmgmt

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

type providerTestError struct {
	code       int
	serverBody string
}

func (e providerTestError) Error() string       { return e.serverBody }
func (e providerTestError) HTTPStatusCode() int { return e.code }

func TestDeploymentLogSkipsProviderGeneratedSecrets(t *testing.T) {
	var out bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&out, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const responseToken = "synthetic-session-issued-only-by-remote"
	provider := slog.New(newDeploymentLog(log)).With("session", responseToken).WithGroup("upstream")
	provider.Debug("sdk request '"+responseToken+"'", slog.Any("response", map[string]string{"session": responseToken}), slog.String("namespace", responseToken))
	provider.Warn("upstream returned "+responseToken, slog.String("stdout", responseToken))
	provider.Info("ssl certificate uploaded", slog.Int("count", 2), slog.String("count", responseToken))
	logs := out.String()
	if strings.Contains(logs, responseToken) || strings.Contains(logs, "response") || strings.Contains(logs, "stdout") || !strings.Contains(logs, "deployment provider SDK request") || !strings.Contains(logs, `"count":2`) {
		t.Fatal("unexpected workflow certificate diagnostics")
	}
	const failure = "deployment failed"
	for _, tc := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("request failed: %s", responseToken), failure},
		{fmt.Errorf("upstream: %w", providerTestError{403, responseToken}), failure + " (HTTP 403)"},
		{providerTestError{123456, responseToken}, failure},
		{fmt.Errorf("%s: %w", responseToken, context.Canceled), context.Canceled.Error()},
	} {
		got := deploymentError(tc.err, failure)
		if got.Error() != tc.want || errors.Unwrap(got) != nil {
			t.Fatal("provider error escaped the workflow boundary")
		}
	}
}
