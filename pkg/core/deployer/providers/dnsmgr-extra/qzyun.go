package dnsmgrextra

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"

	"github.com/certimate-go/certimate/pkg/core"
	"golang.org/x/net/html"
)

const qzyunOrigin = "https://panel.qzyun.cn"
const qzyunRouterState = "%5B%22%22%2C%7B%22children%22%3A%5B%22(app)%22%2C%7B%22children%22%3A%5B%22(product)%22%2C%7B%22children%22%3A%5B%22certificate%22%2C%7B%22children%22%3A%5B%22__PAGE__%22%2C%7B%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%5D%7D%2Cnull%2Cnull%2Ctrue%5D"
const qzyunInitialState = `[{"success":false,"message":""},"$K1"]`

var (
	qzyunDocumentID = regexp.MustCompile(`^[a-zA-Z0-9]{24}$`)
	qzyunActionRef  = regexp.MustCompile(`createServerReference\)\("([a-f0-9]{32,64})",[^)]{0,300},"(login|addCertificateAction|updateCertificateAction|bindDomainCdnServer)"\)`)
)

// The console creates certificates by name without an idempotency key. Runs
// in this Dashboard must observe the preceding account mutation before listing
// and creating. Stripes keep the lock table bounded across credential edits.
var qzyunAccountLocks = func() [64]chan struct{} {
	var locks [64]chan struct{}
	for i := range locks {
		locks[i] = make(chan struct{}, 1)
	}
	return locks
}()

type qzyunSession struct {
	client  *http.Client
	actions map[string]string
	loaded  map[string]bool
}

func deployQzyun(ctx context.Context, client *http.Client, email, password, target, domain, cert, key string) (*core.DeployerDeployResult, error) {
	accountHash := sha256.Sum256([]byte(strings.ToLower(email)))
	lock := qzyunAccountLocks[int(accountHash[0])%len(qzyunAccountLocks)]
	select {
	case lock <- struct{}{}:
		defer func() { <-lock }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	sessionClient := *client
	sessionClient.Jar = jar
	sessionClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	s := qzyunSession{client: &sessionClient, actions: make(map[string]string), loaded: make(map[string]bool)}
	if err := s.login(ctx, email, password); err != nil {
		return nil, fmt.Errorf("Qzyun login: %w", err)
	}
	page, err := s.page(ctx, "/certificate")
	if err != nil {
		return nil, err
	}
	id := target
	if !qzyunDocumentID.MatchString(target) {
		record, err := page.certificate(target)
		if err != nil {
			return nil, err
		}
		id = qzyunString(record, "documentId")
	}

	if id == "" {
		err := s.mutate(ctx, page, "addCertificateAction", map[string]string{
			"1_certificateName": target, "1_serverCertificate": cert, "1_privateKey": key, "0": qzyunInitialState,
		})
		if err != nil {
			return nil, err
		}
		page, err = s.page(ctx, "/certificate")
		if err != nil {
			return nil, fmt.Errorf("Qzyun certificate added; lookup failed: %w", err)
		}
		record, err := page.certificate(target)
		if err != nil {
			return nil, fmt.Errorf("Qzyun certificate added; lookup failed: %w", err)
		}
		id = qzyunString(record, "documentId")
		if id == "" {
			return nil, errors.New("Qzyun certificate added but document ID not found; verify remote state before retrying")
		}
	} else {
		if err := s.mutate(ctx, page, "updateCertificateAction", map[string]string{
			"1_certDocumentId": id, "1_serverCertificate": cert, "1_privateKey": key, "0": qzyunInitialState,
		}); err != nil {
			return nil, err
		}
	}

	if domain != "" {
		if err := s.bind(ctx, domain, id, cert, key); err != nil {
			return nil, fmt.Errorf("Qzyun certificate stored; domain binding: %w", err)
		}
	}
	return &core.DeployerDeployResult{ExtendedData: map[string]any{"documentId": id}}, nil
}

func (s *qzyunSession) bind(ctx context.Context, domain, certificateID, cert, key string) error {
	hostPage, err := s.page(ctx, "/cdn/domain/"+url.PathEscape(domain))
	if err != nil {
		return err
	}
	var hostID, hostDocumentID string
	for _, record := range hostPage.records {
		if qzyunString(record, "domain") != domain {
			continue
		}
		id := qzyunString(record, "id")
		doc := qzyunString(record, "documentId")
		if id == "" || doc == "" {
			continue
		}
		if hostID != "" && (id != hostID || doc != hostDocumentID) {
			return errors.New("multiple matching Qzyun domains")
		}
		hostID, hostDocumentID = id, doc
	}
	if hostID == "" {
		return errors.New("Qzyun domain not found")
	}
	page, err := s.page(ctx, "/certificate")
	if err != nil {
		return err
	}
	record, err := page.certificate(certificateID)
	if err != nil {
		return err
	}
	if record == nil {
		return errors.New("Qzyun certificate not found after upload")
	}
	boundDomains, _ := record["cdnDomains"].([]any)
	for _, entry := range boundDomains {
		host, _ := entry.(map[string]any)
		if qzyunString(host, "domain") == domain {
			return nil
		}
	}
	return s.mutate(ctx, page, "bindDomainCdnServer", map[string]string{
		"1_domainName": domain, "1_Id": hostID, "1_documentId": hostDocumentID, "1_CertificateName": qzyunString(record, "name"),
		"1_ServerCertificate": cert, "1_CertificateDocumentId": certificateID, "1_PrivateKey": key, "0": qzyunInitialState,
	})
}

func (s *qzyunSession) login(ctx context.Context, email, password string) error {
	page, err := s.page(ctx, "/login")
	if err != nil {
		return err
	}
	response, body, err := s.postAction(ctx, page, "login", map[string]string{
		"1_email": email, "1_password": password, "0": `[{"error":null,"success":false},"$K1"]`,
	})
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusOK {
		if result := qzyunResult(body); result != nil && result["success"] != true {
			return errors.New("Qzyun rejected login")
		}
	} else if response.StatusCode < 300 || response.StatusCode >= 400 {
		return fmt.Errorf("Qzyun returned HTTP %d", response.StatusCode)
	}
	// A pre-login tracking cookie alone is insufficient. Require a newly issued
	// cookie which is available for the authenticated certificate page.
	certificateURL, _ := url.Parse(qzyunOrigin + "/certificate")
	for _, issued := range response.Cookies() {
		for _, active := range s.client.Jar.Cookies(certificateURL) {
			if active.Name == issued.Name && active.Value == issued.Value && active.Value != "" && active.Value != "deleted" {
				return nil
			}
		}
	}
	return errors.New("Qzyun did not issue a login session")
}

func (s *qzyunSession) mutate(ctx context.Context, page *qzyunPage, action string, fields map[string]string) error {
	response, body, err := s.postAction(ctx, page, action, fields)
	if err != nil {
		return fmt.Errorf("Qzyun %s: %w", action, err)
	}
	if response.StatusCode != http.StatusOK || qzyunResult(body)["success"] != true {
		return fmt.Errorf("Qzyun did not confirm %s (HTTP %d)", action, response.StatusCode)
	}
	return nil
}

// RSC action results are standalone JSON objects in numbered Flight frames.
// Messages may include a submitted credential, so they stay local to parsing.
func qzyunResult(body []byte) map[string]any {
	var result map[string]any
	for line := range bytes.SplitSeq(body, []byte{'\n'}) {
		id, data, ok := bytes.Cut(line, []byte{':'})
		if !ok || !qzyunFrameID(id) {
			continue
		}
		var record map[string]any
		if json.Unmarshal(data, &record) == nil && (record["success"] != nil || record["error"] != nil || record["message"] != nil) {
			result = record
		}
	}
	return result
}

func qzyunFrameID(id []byte) bool {
	if len(id) == 0 {
		return false
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func (s *qzyunSession) postAction(ctx context.Context, page *qzyunPage, name string, fields map[string]string) (*http.Response, []byte, error) {
	id, err := s.actionID(ctx, page, name)
	if err != nil {
		return nil, nil, err
	}
	var buf bytes.Buffer
	form := multipart.NewWriter(&buf)
	for k, v := range fields {
		if err := form.WriteField(k, v); err != nil {
			return nil, nil, err
		}
	}
	if err := form.Close(); err != nil {
		return nil, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, qzyunOrigin+page.path, &buf)
	if err != nil {
		return nil, nil, errors.New("invalid Qzyun request")
	}
	req.Header.Set("Content-Type", form.FormDataContentType())
	req.Header.Set("Accept", "text/x-component")
	req.Header.Set("Next-Action", id)
	req.Header.Set("Next-Router-State-Tree", qzyunRouterState)
	req.Header.Set("Origin", qzyunOrigin)
	req.Header.Set("Referer", qzyunOrigin+page.path)
	return s.request(req)
}

func (s *qzyunSession) request(req *http.Request) (*http.Response, []byte, error) {
	response, err := s.client.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return nil, nil, req.Context().Err()
		}
		return nil, nil, errors.New("Qzyun connection failed; check remote state before retrying")
	}
	defer response.Body.Close()
	const maxSize = 8 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxSize+1))
	if err != nil || len(body) > maxSize {
		return nil, nil, errors.New("invalid Qzyun response size")
	}
	return response, body, nil
}

func (s *qzyunSession) actionID(ctx context.Context, page *qzyunPage, name string) (string, error) {
	for _, src := range page.scripts {
		if id := s.actions[name]; id != "" {
			return id, nil
		}
		if s.loaded[src] {
			continue
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
		if err != nil {
			return "", errors.New("invalid Qzyun script URL")
		}
		response, body, err := s.request(req)
		if err != nil {
			return "", err
		}
		if response.StatusCode != http.StatusOK {
			continue
		}
		s.loaded[src] = true
		for _, match := range qzyunActionRef.FindAllSubmatch(body, -1) {
			s.actions[string(match[2])] = string(match[1])
		}
	}
	if id := s.actions[name]; id != "" {
		return id, nil
	}
	return "", fmt.Errorf("Qzyun page does not declare %s", name)
}

type qzyunPage struct {
	path             string
	scripts          []string
	records          []map[string]any
	hasEmptyCertList bool
}

func (s *qzyunSession) page(ctx context.Context, path string) (*qzyunPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, qzyunOrigin+path, nil)
	if err != nil {
		return nil, errors.New("invalid Qzyun page URL")
	}
	response, body, err := s.request(req)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Qzyun page returned HTTP %d", response.StatusCode)
	}
	return qzyunReadPage(body, req.URL), nil
}

func qzyunReadPage(body []byte, address *url.URL) *qzyunPage {
	page := &qzyunPage{path: address.EscapedPath()}
	z := html.NewTokenizer(bytes.NewReader(body))
	var stream strings.Builder
	var script bool
	for {
		kind := z.Next()
		if kind == html.ErrorToken {
			break
		}
		if kind == html.TextToken && script {
			raw := strings.TrimSuffix(strings.TrimSpace(string(z.Text())), ";")
			if chunk, ok := strings.CutPrefix(raw, "self.__next_f.push("); ok {
				var values []json.RawMessage
				if json.Unmarshal([]byte(strings.TrimSuffix(chunk, ")")), &values) == nil && len(values) == 2 && string(values[0]) == "1" {
					var text string
					if json.Unmarshal(values[1], &text) == nil {
						stream.WriteString(text)
					}
				}
			}
		}
		script = false
		if kind != html.StartTagToken {
			continue
		}
		tag, hasAttr := z.TagName()
		script = string(tag) == "script"
		if !script {
			continue
		}
		for hasAttr {
			key, value, more := z.TagAttr()
			hasAttr = more
			if string(key) != "src" {
				continue
			}
			src, err := address.Parse(string(value))
			if err == nil && src.Scheme == "https" && src.Host == address.Host && src.User == nil && strings.HasSuffix(src.Path, ".js") {
				page.scripts = append(page.scripts, src.String())
			}
		}
	}
	// Flight splits model data across script tags. Reassemble before parsing
	// and inspect nested records without assuming a particular property order.
	for line := range strings.SplitSeq(stream.String(), "\n") {
		id, data, ok := strings.Cut(line, ":")
		if !ok || !qzyunFrameID([]byte(id)) || !json.Valid([]byte(data)) {
			continue
		}
		var model any
		decoder := json.NewDecoder(strings.NewReader(data))
		decoder.UseNumber()
		if decoder.Decode(&model) == nil {
			page.collect(model)
		}
	}
	return page
}

func (p *qzyunPage) collect(value any) {
	switch v := value.(type) {
	case map[string]any:
		// An unknown page after a panel upgrade must not trigger certificate
		// creation. An empty list needs a recognizable certificate property.
		for _, key := range []string{"certificates", "initialCertificates", "certificateList", "certs"} {
			if list, ok := v[key].([]any); ok && len(list) == 0 {
				p.hasEmptyCertList = true
			}
		}
		if qzyunString(v, "documentId") != "" {
			p.records = append(p.records, v)
		}
		for _, field := range v {
			p.collect(field)
		}
	case []any:
		for _, field := range v {
			p.collect(field)
		}
	}
}

func qzyunString(record map[string]any, key string) string {
	switch v := record[key].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	}
	return ""
}

func (p *qzyunPage) certificate(target string) (map[string]any, error) {
	readable := p.hasEmptyCertList
	var match map[string]any
	for _, record := range p.records {
		name := qzyunString(record, "name")
		doc := qzyunString(record, "documentId")
		if name == "" {
			continue
		}
		if _, ok := record["content"]; !ok {
			if name == target || doc == target {
				return nil, errors.New("incomplete Qzyun certificate record")
			}
			continue
		}
		if !qzyunDocumentID.MatchString(doc) {
			return nil, errors.New("invalid Qzyun certificate document ID")
		}
		readable = true
		if target != doc && target != name {
			continue
		}
		if match != nil && qzyunString(match, "documentId") != doc {
			return nil, errors.New("multiple matching Qzyun certificates; select a document ID")
		}
		match = record
	}
	if !readable {
		return nil, errors.New("unrecognized Qzyun certificate list")
	}
	return match, nil
}
