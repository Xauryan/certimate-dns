package k8ssecret

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	networking "k8s.io/api/networking/v1"
	meta "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func makeIngressCertificate(t *testing.T) (string, string) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour),
		DNSNames:    []string{"*.example.test", "*.wild.test", "127.0.0.3"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.2")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	derKey, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: derKey}))
}

func TestDeployIngressBinding(t *testing.T) {
	cert, key := makeIngressCertificate(t)
	const secretURL = "/api/v1/namespaces/web/secrets"
	const ingressURL = "/apis/networking.k8s.io/v1/namespaces/web/ingresses/front"
	for _, tc := range []struct {
		name         string
		targets      []string
		denyPatch    bool
		secretFails  bool
		uncovered    bool
		staleBinding bool
		otherBound   bool
		wrongKey     bool
	}{
		{name: "legacy secret only"},
		{name: "bind selected ingress with conflict retry", targets: []string{"front", "front"}},
		{name: "report partial deployment", targets: []string{"front"}, denyPatch: true},
		{name: "failed secret write skips ingress patch", targets: []string{"front"}, secretFails: true},
		{name: "no covered host", targets: []string{"front"}, uncovered: true},
		{name: "preserve existing TLS when replacement misses a bound host", targets: []string{"front"}, staleBinding: true},
		{name: "covered hosts all bound to another secret", targets: []string{"front"}, otherBound: true},
		{name: "mismatched key", targets: []string{"front"}, wrongKey: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const secret = "web-cert"
			ing := networking.Ingress{
				TypeMeta:   meta.TypeMeta{Kind: "Ingress", APIVersion: "networking.k8s.io/v1"},
				ObjectMeta: meta.ObjectMeta{Namespace: "web", Name: "front", ResourceVersion: "1"},
				Spec: networking.IngressSpec{
					TLS: []networking.IngressTLS{
						{SecretName: secret, Hosts: []string{"already.example.test"}},
						{SecretName: "other-cert", Hosts: []string{"other.example.test"}},
					},
					Rules: []networking.IngressRule{
						{Host: ""}, {Host: "selected.example.test"}, {Host: "other.example.test"}, {Host: "selected.example.test"},
						{Host: "*.wild.test"}, {Host: "too.deep.example.test"}, {Host: "unrelated.test"}, {Host: "*.selected.example.test"},
						{Host: "127.0.0.2"}, {Host: "127.0.0.3"}, {Host: "example.test"},
					},
				},
			}
			if tc.uncovered {
				ing.Spec.Rules = []networking.IngressRule{{Host: "unrelated.test"}}
			}
			if tc.staleBinding {
				ing.Spec.TLS[0].Hosts = []string{"unrelated.test"}
			}
			if tc.otherBound {
				ing.Spec.Rules = []networking.IngressRule{{Host: "other.example.test"}}
			}
			secretWrites, ingressGets, ingressPatches := 0, 0, 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.URL.Path == secretURL+"/"+secret && r.Method == http.MethodGet:
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":404,"reason":"NotFound"}`))
				case r.URL.Path == secretURL && r.Method == http.MethodPost:
					secretWrites++
					if tc.secretFails {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":403,"reason":"Forbidden","message":"provider-echoed-key-material"}`))
						return
					}
					_, _ = w.Write([]byte(`{"kind":"Secret","apiVersion":"v1"}`))
				case r.URL.Path == ingressURL && r.Method == http.MethodGet:
					ingressGets++
					_ = json.NewEncoder(w).Encode(ing)
				case r.URL.Path == ingressURL && r.Method == http.MethodPatch:
					ingressPatches++
					var patch struct {
						Metadata struct{ ResourceVersion string }
						Spec     struct{ TLS []networking.IngressTLS }
					}
					dec := json.NewDecoder(r.Body)
					dec.DisallowUnknownFields()
					if err := dec.Decode(&patch); err != nil || patch.Metadata.ResourceVersion != ing.ResourceVersion || r.Header.Get("Content-Type") != "application/merge-patch+json" {
						t.Error("unexpected TLS patch or resource version")
					}
					if tc.denyPatch {
						w.WriteHeader(http.StatusForbidden)
						_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":403,"reason":"Forbidden","message":"provider-echoed-key-material"}`))
						return
					}
					if ingressPatches == 1 {
						ing.ResourceVersion = "2"
						ing.Spec.TLS = append(ing.Spec.TLS, networking.IngressTLS{SecretName: "concurrent-cert", Hosts: []string{"concurrent.example.test"}})
						w.WriteHeader(http.StatusConflict)
						_, _ = w.Write([]byte(`{"kind":"Status","apiVersion":"v1","status":"Failure","code":409,"reason":"Conflict"}`))
						return
					}
					if len(patch.Spec.TLS) != 3 || !slices.Equal(patch.Spec.TLS[0].Hosts, []string{"already.example.test", "selected.example.test", "*.wild.test", "127.0.0.2"}) ||
						patch.Spec.TLS[0].SecretName != secret || patch.Spec.TLS[1].SecretName != "other-cert" || !slices.Equal(patch.Spec.TLS[1].Hosts, ing.Spec.TLS[1].Hosts) ||
						patch.Spec.TLS[2].SecretName != "concurrent-cert" || !slices.Equal(patch.Spec.TLS[2].Hosts, ing.Spec.TLS[2].Hosts) {
						t.Error("TLS bindings lost or broadened")
					}
					ing.Spec.TLS = patch.Spec.TLS
					_ = json.NewEncoder(w).Encode(ing)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			t.Cleanup(srv.Close)
			cfg := &DeployerConfig{
				KubeConfig: strings.Replace(testKubeConfig, "https://127.0.0.1:6443", srv.URL, 1), Namespace: "web",
				SecretName: secret, SecretType: "kubernetes.io/tls", SecretDataKeyForKey: "tls.key", SecretDataKeyForCrt: "tls.crt",
				Ingresses: tc.targets,
			}
			d, err := NewDeployer(cfg)
			if err != nil {
				t.Fatal(err)
			}
			deployKey := key
			if tc.wrongKey {
				_, deployKey = makeIngressCertificate(t)
			}
			_, err = d.Deploy(context.Background(), cert, deployKey)
			if err != nil && strings.Contains(err.Error(), "provider-echoed-key-material") {
				t.Fatal("raw provider error exposed")
			}
			if tc.wrongKey {
				if err == nil || !strings.Contains(err.Error(), "mismatched private key") || ingressGets != 0 || secretWrites != 0 {
					t.Fatal("expected key validation before API access")
				}
				return
			}
			if tc.uncovered || tc.staleBinding || tc.otherBound {
				want := "does not cover any named Ingress rule host"
				if tc.staleBinding {
					want = "does not cover an existing TLS host"
				}
				if tc.otherBound {
					want = "already bound to other Secrets"
				}
				if err == nil || !strings.Contains(err.Error(), want) || ingressGets != 1 || secretWrites != 0 || ingressPatches != 0 {
					t.Fatal("expected a clear preflight error and no mutations")
				}
				return
			}
			if tc.secretFails {
				if err == nil || ingressGets != 1 || ingressPatches != 0 {
					t.Error("attempted Ingress binding after failed Secret write")
				}
				return
			}
			if tc.denyPatch {
				if err == nil || !strings.Contains(err.Error(), "Secret updated") || ingressPatches != 1 {
					t.Error("expected partial deployment error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if secretWrites != 1 {
				t.Fatalf("unexpected Secret writes: %d", secretWrites)
			}
			if len(tc.targets) == 0 {
				if ingressGets != 0 || ingressPatches != 0 {
					t.Error("legacy deployment accessed Ingress")
				}
				return
			}
			if _, err := d.Deploy(context.Background(), cert, key); err != nil {
				t.Fatal(err)
			}
			if ingressGets != 3 || ingressPatches != 2 {
				t.Fatalf("unexpected request count: GET %d PATCH %d", ingressGets, ingressPatches)
			}
		})
	}
}

func TestRejectInvalidIngressNamesBeforeDeployment(t *testing.T) {
	d, _ := NewDeployer(&DeployerConfig{
		Namespace: "web", SecretName: "web-cert", SecretType: "kubernetes.io/tls",
		SecretDataKeyForKey: "tls.key", SecretDataKeyForCrt: "tls.crt", Ingresses: []string{"../other"},
	})
	_, err := d.Deploy(context.Background(), "", "")
	if err == nil || !strings.Contains(err.Error(), "Ingress name") {
		t.Fatal("expected name validation before any API access")
	}
}
