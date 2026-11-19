package k8ssecret

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"

	networking "k8s.io/api/networking/v1"
	k8serrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/util/retry"

	"github.com/certimate-go/certimate/pkg/utils/cert/hostname"
)

type ingressBinding struct {
	name  string
	patch []byte
}

func (d *Deployer) ingressRequest(req *rest.Request, name string) *rest.Request {
	return req.AbsPath("apis", "networking.k8s.io", "v1").
		Namespace(d.config.Namespace).Resource("ingresses").Name(name)
}

func (d *Deployer) planIngressBinding(ctx context.Context, client *rest.RESTClient, name string, cert *x509.Certificate) ([]byte, error) {
	var ing networking.Ingress
	if err := d.ingressRequest(client.Get(), name).Do(ctx).Into(&ing); err != nil {
		return nil, summarizeAPIError(err)
	}
	if ing.ResourceVersion == "" || ing.Name != name || ing.Namespace != d.config.Namespace {
		return nil, fmt.Errorf("incomplete or mismatched Ingress metadata")
	}

	tlsEntries := ing.Spec.TLS
	entry := -1
	targetHosts := make(map[string]bool)
	bound := make(map[string]bool)
	for i, tls := range tlsEntries {
		isTarget := tls.SecretName == d.config.SecretName
		if isTarget && entry < 0 {
			entry = i
		}
		for _, host := range tls.Hosts {
			bound[host] = true
			if isTarget {
				if !hostname.IsMatchByCertificate(cert, host) {
					return nil, fmt.Errorf("replacement certificate does not cover an existing TLS host bound to the selected Secret")
				}
				targetHosts[host] = true
			}
		}
	}

	var newHosts []string
	covered, boundToTarget := false, false
	for _, rule := range ing.Spec.Rules {
		if rule.Host == "" || !hostname.IsMatchByCertificate(cert, rule.Host) {
			continue
		}
		covered = true
		if targetHosts[rule.Host] {
			boundToTarget = true
		}
		if !bound[rule.Host] {
			newHosts = append(newHosts, rule.Host)
			bound[rule.Host] = true
		}
	}
	if !covered {
		return nil, errors.New("certificate does not cover any named Ingress rule host")
	}
	if len(newHosts) == 0 {
		if !boundToTarget {
			return nil, errors.New("all covered Ingress rule hosts are already bound to other Secrets")
		}
		return nil, nil
	}
	if entry < 0 {
		tlsEntries = append(tlsEntries, networking.IngressTLS{SecretName: d.config.SecretName, Hosts: newHosts})
	} else {
		tlsEntries[entry].Hosts = append(tlsEntries[entry].Hosts, newHosts...)
	}
	return json.Marshal(map[string]any{
		"metadata": map[string]string{"resourceVersion": ing.ResourceVersion},
		"spec":     map[string]any{"tls": tlsEntries},
	})
}

// Apply just spec.tls. When a concurrent change invalidates the prepared patch,
// re-evaluate the new rule hosts and bindings against the certificate.
func (d *Deployer) bindIngressTLS(ctx context.Context, client *rest.RESTClient, binding ingressBinding, cert *x509.Certificate) error {
	fetchAgain := false
	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		if fetchAgain {
			patch, err := d.planIngressBinding(ctx, client, binding.name, cert)
			if err != nil {
				return err
			}
			binding.patch = patch
		}
		if len(binding.patch) == 0 {
			return nil
		}
		fetchAgain = true
		err := d.ingressRequest(client.Patch(types.MergePatchType), binding.name).Body(binding.patch).Do(ctx).Error()
		if err != nil && !k8serrs.IsConflict(err) {
			return summarizeAPIError(err)
		}
		return err
	})
	if k8serrs.IsConflict(err) {
		return summarizeAPIError(err)
	}
	return err
}
