package qiniusslcert

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	qiniu "github.com/qiniu/go-sdk/v7/client"
)

type transportFunc func(*http.Request) (*http.Response, error)

func (f transportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestUploadOnlyProtocol(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	pair := server.TLS.Certificates[0]
	server.Close()
	der, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	var calls []string
	original := qiniu.DefaultTransport
	t.Cleanup(func() { qiniu.DefaultTransport = original })
	qiniu.DefaultTransport = transportFunc(func(r *http.Request) (*http.Response, error) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		body := ""
		switch r.Method + " " + r.URL.Path {
		case "GET /sslcert":
			body = `{"certs":[],"marker":""}`
		case "POST /sslcert":
			var input struct {
				CA      string `json:"ca"`
				Private string `json:"pri"`
			}
			if err := json.NewDecoder(r.Body).Decode(&input); err != nil || input.CA != cert || input.Private != key {
				t.Fatal("invalid upload material")
			}
			body = `{"certID":"uploaded-id"}`
		default:
			t.Fatal("unexpected binding or cleanup request")
		}
		return &http.Response{StatusCode: 200, ContentLength: int64(len(body)), Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"application/json"}}}, nil
	})
	if _, err := New("", "synthetic"); err == nil {
		t.Fatal("empty access key accepted")
	}
	d, err := New("synthetic-id", "synthetic-secret")
	if err != nil {
		t.Fatal(err)
	}
	result, err := d.Deploy(context.Background(), cert, key)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExtendedData["certificateId"] != "uploaded-id" || !reflect.DeepEqual(calls, []string{"GET /sslcert", "POST /sslcert"}) {
		t.Fatal("unexpected upload protocol")
	}
	if _, err := d.Deploy(context.Background(), cert, "invalid"); err == nil || len(calls) != 2 {
		t.Fatal("sent invalid key")
	}
}
