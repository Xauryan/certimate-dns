package dnsmanagement

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
)

const (
	contractZone        = "example.test"
	contractForeignZone = "outside.test"
	contractInitial     = "fixture-original"
	contractUpdated     = "fixture-updated"
	contractUnrelated   = "fixture-keep"
	contractRemark      = "fixture-record-comment"
	contractDiagnostic  = "fixture-provider-diagnostic"
	contractPageTotal   = dns.DNSPageSize + 1
)

type dnsContractStep struct {
	method, target, query, body, reply string
	status                             int
}

type dnsContractFixture struct {
	provider, endpoint, actionHeader     string
	auth, discoveryAuth                  string
	config                               map[string]any
	zone, foreignZone, record, unrelated string
	create                               dns.RecordInput
	steps                                []dnsContractStep
}

func TestInitialDNSProvidersShareRecordContract(t *testing.T) {
	for _, fixture := range []func(string, string) dnsContractFixture{aliDNSContract, dnsPodContract, cloudflareContract} {
		for _, owner := range []struct{ label, name, testName string }{
			{"@", contractZone, "apex"},
			{"*", "*." + contractZone, "wildcard"},
		} {
			f := fixture(owner.name, owner.label)
			t.Run(f.provider+"/"+owner.testName, func(t *testing.T) {
				a := &domain.Access{Provider: f.provider, Config: f.config, DNSManagementTransport: f.transport(t)}
				discovery, err := Open(a, true)
				if err != nil {
					t.Fatal(err)
				}
				p, err := Open(a, false)
				if err != nil {
					t.Fatal(err)
				}
				ctx := t.Context()
				zones, err := discovery.Zones(ctx, 2)
				if err != nil || zones.Info != (dns.PageInfo{Page: 2, Total: contractPageTotal}) || len(zones.Items) != 1 ||
					zones.Items[0].ID != f.zone || zones.Items[0].Name != contractZone {
					t.Fatalf("zone page: %+v, %v", zones, err)
				}
				input := f.create
				input.Name, input.Type, input.Content, input.TTL = owner.name, "TXT", contractInitial, 600
				checkRecords := func(contents map[string]dns.RecordPatch) {
					t.Helper()
					records, err := p.DNSRecords(ctx, f.zone, 2, owner.name)
					if err != nil || records.Info != (dns.PageInfo{Page: 2, Total: dns.DNSPageSize + len(contents)}) || len(records.Items) != len(contents) {
						t.Fatalf("record page: %+v, %v", records, err)
					}
					for _, record := range records.Items {
						want, exists := contents[record.ID]
						remark := input.Description
						if record.ID == f.unrelated {
							remark = contractRemark
						}
						if !exists || record.Name != owner.name || record.Type != "TXT" || record.Content != want.Content ||
							record.TTL != want.TTL || record.Line != f.create.Line || record.Description != remark {
							t.Fatalf("unexpected record: %+v", record)
						}
						if record.ID == f.record && input.Weight != nil && (record.Weight == nil || *record.Weight != *input.Weight) {
							t.Fatalf("record %s lost its weight", record.ID)
						}
						delete(contents, record.ID)
					}
				}
				unrelated := dns.RecordPatch{Content: contractUnrelated, TTL: 600}
				checkRecords(map[string]dns.RecordPatch{f.unrelated: unrelated})
				id, err := p.CreateDNSRecord(ctx, f.zone, input)
				if err != nil || id != f.record {
					t.Fatalf("create: %q, %v", id, err)
				}
				checkRecords(map[string]dns.RecordPatch{
					f.unrelated: unrelated, id: {Content: input.Content, TTL: input.TTL},
				})
				patch := dns.RecordPatch{Content: contractUpdated, TTL: 900}
				if _, err := p.PatchDNSRecord(ctx, f.foreignZone, id, patch); err == nil {
					t.Fatal("patch accepted a record from another zone")
				}
				if _, err := p.DeleteDNSRecord(ctx, f.foreignZone, id); err == nil {
					t.Fatal("delete accepted a record from another zone")
				}
				if saved, err := p.PatchDNSRecord(ctx, f.zone, id, patch); err != nil || saved != id {
					t.Fatalf("patch: %q, %v", saved, err)
				}
				checkRecords(map[string]dns.RecordPatch{f.unrelated: unrelated, id: patch})
				if removed, err := p.DeleteDNSRecord(ctx, f.zone, id); err != nil || removed != id {
					t.Fatalf("delete: %q, %v", removed, err)
				}
				checkRecords(map[string]dns.RecordPatch{f.unrelated: unrelated})
				for _, page := range []int{3, 4} {
					if _, err := discovery.Zones(ctx, page); err == nil || strings.Contains(err.Error(), contractDiagnostic) {
						t.Fatalf("zone list failure on page %d was accepted or leaked provider details: %v", page, err)
					}
				}
			})
		}
	}
}

func (f dnsContractFixture) transport(t *testing.T) *http.Transport {
	t.Helper()
	next := 0
	transport := &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		return nil, errors.New("network disabled for DNS contract test")
	}}
	t.Cleanup(func() {
		if next != len(f.steps) {
			t.Errorf("consumed %d of %d provider requests", next, len(f.steps))
		}
	})
	// The real SDK generates and authenticates requests. Every exchange is
	// matched in order here, so an additional write cannot reach the network.
	transport.RegisterProtocol("https", mockRPC(func(r *http.Request) (*http.Response, error) {
		if next >= len(f.steps) {
			t.Fatalf("unexpected provider request after step %d", next)
		}
		step := f.steps[next]
		next++
		target := r.URL.Path
		if f.actionHeader != "" {
			target = contractHeader(r.Header, f.actionHeader)
		}
		if r.URL.Host != f.endpoint || r.Method != step.method || target != step.target {
			t.Fatalf("request %d: got %s %s %s, want %s %s %s", next, r.Method, r.URL.Host, target, step.method, f.endpoint, step.target)
		}
		auth := f.auth
		if f.discoveryAuth != "" && step.target == "/client/v4/zones" {
			auth = f.discoveryAuth
		}
		value := contractHeader(r.Header, "Authorization")
		if f.actionHeader == "" && value != auth ||
			f.actionHeader != "" && (!strings.HasPrefix(value, auth) || !strings.Contains(value, "Signature=")) {
			t.Fatalf("request %d lacks expected authentication", next)
		}
		query, err := url.ParseQuery(step.query)
		if err != nil || r.URL.Query().Encode() != query.Encode() {
			t.Fatalf("request %d query: got %v, want %v, error %v", next, r.URL.Query(), query, err)
		}
		var body []byte
		if r.Body != nil {
			defer r.Body.Close()
			body, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
		}
		if len(body) != 0 || step.body != "" {
			var got, want any
			if json.Unmarshal(body, &got) != nil || json.Unmarshal([]byte(step.body), &want) != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("request %d body: got %s, want %s", next, body, step.body)
			}
		}
		response := jsonRPC(step.reply)
		if step.status != 0 {
			response.StatusCode = step.status
		}
		return response, nil
	}))
	return transport
}

func contractHeader(h http.Header, name string) string {
	// The Alibaba SDK constructs its header map with lowercase keys.
	for key, values := range h {
		if strings.EqualFold(key, name) && len(values) != 0 {
			return values[0]
		}
	}
	return ""
}

func aliDNSContract(_, label string) dnsContractFixture {
	const id, unrelated, line = "234", "345", "telecom"
	rpc := func(action, query, reply string) dnsContractStep {
		return dnsContractStep{method: http.MethodPost, target: action, query: query, reply: reply}
	}
	zonePage := func(page int, reply string) dnsContractStep {
		return rpc("DescribeDomains", fmt.Sprintf("PageNumber=%d&PageSize=%d&ResourceGroupId=fixture-group", page, dns.DNSPageSize), reply)
	}
	record := func(id, content string, ttl int) string {
		remark := ""
		if id == unrelated {
			remark = contractRemark
		}
		return fmt.Sprintf(`{"DomainName":%q,"RecordId":%q,"RR":%q,"Type":"TXT","Value":%q,"TTL":%d,"Line":%q,"Locked":false,"Remark":%q}`,
			contractZone, id, label, content, ttl, line, remark)
	}
	z := rpc("DescribeDomainInfo", "DomainName="+contractZone, `{"DomainName":"example.test","ResourceGroupId":"fixture-group"}`)
	foreign := rpc("DescribeDomainInfo", "DomainName="+contractForeignZone, `{"DomainName":"outside.test","ResourceGroupId":"fixture-group"}`)
	lookup := rpc("DescribeDomainRecordInfo", "RecordId="+id, record(id, contractInitial, 600))
	lookupUpdated := rpc("DescribeDomainRecordInfo", "RecordId="+id, record(id, contractUpdated, 900))
	list := func(records ...string) dnsContractStep {
		query := fmt.Sprintf("DomainName=%s&PageNumber=2&PageSize=%d&RRKeyWord=%s&SearchMode=LIKE", contractZone, dns.DNSPageSize, url.QueryEscape(label))
		return rpc("DescribeDomainRecords", query, fmt.Sprintf(`{"TotalCount":%d,"DomainRecords":{"Record":[%s]}}`, dns.DNSPageSize+len(records), strings.Join(records, ",")))
	}
	keep := record(unrelated, contractUnrelated, 600)
	limited := zonePage(3, `{"Code":"Throttling.User","Message":"`+contractDiagnostic+`"}`)
	limited.status = http.StatusTooManyRequests
	denied := zonePage(4, `{"Code":"Forbidden","Message":"`+contractDiagnostic+`"}`)
	denied.status = http.StatusForbidden
	return dnsContractFixture{
		provider: "aliyun", endpoint: "alidns.aliyuncs.com", actionHeader: "X-Acs-Action", auth: "ACS3-HMAC-SHA256 Credential=fixture-id,",
		config: map[string]any{"accessKeyId": "fixture-id", "accessKeySecret": "fixture-secret", "resourceGroupId": "fixture-group"},
		zone:   contractZone, foreignZone: contractForeignZone, record: id, unrelated: unrelated,
		create: dns.RecordInput{Line: line},
		steps: []dnsContractStep{
			zonePage(2, fmt.Sprintf(`{"TotalCount":%d,"Domains":{"Domain":[{"DomainName":%q}]}}`, contractPageTotal, contractZone)),
			z, list(keep),
			z, rpc("AddDomainRecord", "DomainName="+contractZone+"&RR="+url.QueryEscape(label)+"&Type=TXT&Line="+line+"&TTL=600&Value="+contractInitial, `{"RecordId":"234"}`),
			z, list(keep, record(id, contractInitial, 600)),
			foreign, lookup, foreign, lookup,
			z, lookup, rpc("UpdateDomainRecord", "RecordId="+id+"&RR="+url.QueryEscape(label)+"&Type=TXT&Line="+line+"&TTL=900&Value="+contractUpdated, `{"RecordId":"234"}`),
			z, list(keep, record(id, contractUpdated, 900)),
			z, lookupUpdated, rpc("DeleteDomainRecord", "RecordId="+id, `{"RecordId":"234"}`),
			z, list(keep),
			limited, denied,
		},
	}
}

func dnsPodContract(_, label string) dnsContractFixture {
	const id, unrelated, line = "234", "345", "10=1"
	rpc := func(action, body, reply string) dnsContractStep {
		return dnsContractStep{method: http.MethodPost, target: action, body: body, reply: `{"Response":{` + reply + `,"RequestId":"fixture"}}`}
	}
	zonePage := func(page int, reply string) dnsContractStep {
		return rpc("DescribeDomainList", fmt.Sprintf(`{"Offset":%d,"Limit":%d}`, (page-1)*dns.DNSPageSize, dns.DNSPageSize), reply)
	}
	record := func(id, content string, ttl int) string {
		return fmt.Sprintf(`{"RecordId":%s,"Name":%q,"Type":"TXT","Value":%q,"TTL":%d,"LineId":%q,"Remark":%q,"Weight":7}`,
			id, label, content, ttl, line, contractRemark)
	}
	list := func(records ...string) dnsContractStep {
		body := fmt.Sprintf(`{"Domain":%q,"Offset":%d,"Limit":%d,"Keyword":%q}`, contractZone, dns.DNSPageSize, dns.DNSPageSize, label)
		return rpc("DescribeRecordList", body, fmt.Sprintf(`"RecordCountInfo":{"TotalCount":%d},"RecordList":[%s]`, dns.DNSPageSize+len(records), strings.Join(records, ",")))
	}
	key := fmt.Sprintf(`"Domain":%q,"RecordId":%s`, contractZone, id)
	lookup := rpc("DescribeRecord", "{"+key+"}", fmt.Sprintf(
		`"RecordInfo":{"Id":%s,"SubDomain":%q,"RecordType":"TXT","RecordLine":"联通","RecordLineId":%q,"Enabled":1,"Weight":7,"Remark":%q}`, id, label, line, contractRemark))
	foreign := rpc("DescribeRecord", fmt.Sprintf(`{"Domain":%q,"RecordId":%s}`, contractForeignZone, id), `"Error":{"Code":"ResourceNotFound.NoDataOfRecord","Message":"outside zone"}`)
	keep := record(unrelated, contractUnrelated, 600)
	limited := zonePage(3, `"Error":{"Code":"RequestLimitExceeded","Message":"`+contractDiagnostic+`"}`)
	limited.status = http.StatusTooManyRequests
	denied := zonePage(4, `"Error":{"Code":"UnauthorizedOperation","Message":"`+contractDiagnostic+`"}`)
	denied.status = http.StatusForbidden
	return dnsContractFixture{
		provider: "tencentcloud", endpoint: "dnspod.tencentcloudapi.com", actionHeader: "X-TC-Action", auth: "TC3-HMAC-SHA256 Credential=fixture-id/",
		config: map[string]any{"secretId": "fixture-id", "secretKey": "fixture-secret"},
		zone:   contractZone, foreignZone: contractForeignZone, record: id, unrelated: unrelated,
		create: dns.RecordInput{Line: line, Description: contractRemark, Weight: ptr(7)},
		steps: []dnsContractStep{
			zonePage(2, fmt.Sprintf(`"DomainCountInfo":{"DomainTotal":%d},"DomainList":[{"Name":%q}]`, contractPageTotal, contractZone)),
			list(keep),
			rpc("CreateRecord", fmt.Sprintf(`{"Domain":%q,"SubDomain":%q,"RecordType":"TXT","RecordLine":"默认","RecordLineId":%q,"Value":%q,"TTL":600,"Weight":7,"Remark":%q}`,
				contractZone, label, line, contractInitial, contractRemark), `"RecordId":234`),
			list(keep, record(id, contractInitial, 600)),
			foreign, foreign,
			lookup, rpc("ModifyRecord", fmt.Sprintf(`{%s,"SubDomain":%q,"RecordType":"TXT","RecordLine":"联通","RecordLineId":%q,"Value":%q,"TTL":900,"Weight":7,"Remark":%q,"Status":"ENABLE"}`,
				key, label, line, contractUpdated, contractRemark), `"RecordId":234`),
			list(keep, record(id, contractUpdated, 900)),
			lookup, rpc("DeleteRecord", "{"+key+"}", `"RecordId":234`),
			list(keep),
			limited, denied,
		},
	}
}

func cloudflareContract(name, _ string) dnsContractFixture {
	const zones = "/client/v4/zones"
	const zone, foreign = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	const id, unrelated, line = "cccccccccccccccccccccccccccccccc", "dddddddddddddddddddddddddddddddd", "0"
	const records = zones + "/" + zone + "/dns_records"
	const detail = records + "/" + id
	const foreignDetail = zones + "/" + foreign + "/dns_records/" + id
	page := func(target string, page, total int, query string, items ...string) dnsContractStep {
		return dnsContractStep{method: http.MethodGet, target: target, query: fmt.Sprintf("page=%d&per_page=%d%s", page, dns.DNSPageSize, query),
			reply: fmt.Sprintf(`{"success":true,"result_info":{"page":%d,"total_count":%d},"result":[%s]}`, page, total, strings.Join(items, ","))}
	}
	record := func(id, content string, ttl int) string {
		return fmt.Sprintf(`{"id":%q,"name":%q,"type":"TXT","content":%q,"ttl":%d,"proxied":false,"comment":%q}`,
			id, name, content, ttl, contractRemark)
	}
	list := func(rows ...string) dnsContractStep {
		return page(records, 2, dns.DNSPageSize+len(rows), "&name.contains="+url.QueryEscape(name), rows...)
	}
	success := func(method, target, body, reply string) dnsContractStep {
		return dnsContractStep{method: method, target: target, body: body, reply: `{"success":true,"result":` + reply + `}`}
	}
	writeReply := `{"id":"` + id + `"}`
	failed := `{"success":false,"errors":[{"code":1000,"message":"` + contractDiagnostic + `"}]}`
	outside := dnsContractStep{method: http.MethodGet, target: foreignDetail, reply: failed, status: http.StatusNotFound}
	keep := record(unrelated, contractUnrelated, 600)
	return dnsContractFixture{
		provider: "cloudflare", endpoint: "api.cloudflare.com", auth: "Bearer fixture-dns", discoveryAuth: "Bearer fixture-zones",
		config: map[string]any{"apiToken": "fixture-dns", "apiTokenForZone": "fixture-zones"},
		zone:   zone, foreignZone: foreign, record: id, unrelated: unrelated,
		create: dns.RecordInput{Line: line, Description: contractRemark},
		steps: []dnsContractStep{
			page(zones, 2, contractPageTotal, "", fmt.Sprintf(`{"id":%q,"name":%q,"status":"active"}`, zone, contractZone)),
			list(keep),
			success(http.MethodPost, records, fmt.Sprintf(`{"name":%q,"type":"TXT","content":%q,"ttl":600,"proxied":false,"comment":%q}`, name, contractInitial, contractRemark), writeReply),
			list(keep, record(id, contractInitial, 600)),
			outside, outside,
			success(http.MethodGet, detail, "", record(id, contractInitial, 600)),
			success(http.MethodPatch, detail, fmt.Sprintf(`{"content":%q,"ttl":900}`, contractUpdated), writeReply),
			list(keep, record(id, contractUpdated, 900)),
			success(http.MethodGet, detail, "", record(id, contractUpdated, 900)),
			success(http.MethodDelete, detail, "", writeReply),
			list(keep),
			{method: http.MethodGet, target: zones, query: fmt.Sprintf("page=3&per_page=%d", dns.DNSPageSize), status: http.StatusTooManyRequests, reply: failed},
			{method: http.MethodGet, target: zones, query: fmt.Sprintf("page=4&per_page=%d", dns.DNSPageSize), status: http.StatusForbidden, reply: failed},
		},
	}
}
