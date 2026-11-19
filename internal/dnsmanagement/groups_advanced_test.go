package dnsmanagement

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	api "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/certimate-go/certimate/internal/domain"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
)

type advancedTransport func(*http.Request) (*http.Response, error)

func (f advancedTransport) Call(r *http.Request, _ *http.Transport) (*http.Response, error) {
	return f(r)
}
func (f advancedTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func advancedResponse(body string) *http.Response {
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}
}
func TestAliAdvancedOperations(t *testing.T) {
	ctx := t.Context()
	writes := 0
	transport := advancedTransport(func(r *http.Request) (*http.Response, error) {
		q := r.URL.Query()
		action := r.Header.Get("X-Acs-Action")
		if action == "" {
			action = q.Get("Action")
		}
		if action == "" {
			for name, values := range r.Header {
				if strings.EqualFold(name, "x-acs-action") && len(values) > 0 {
					action = values[0]
					break
				}
			}
		}
		switch action {
		case "DescribeRecordGroups":
			if q.Get("DomainName") != "example.org" || q.Get("PageNumber") != "1" {
				t.Errorf("incorrect domain or page")
			}
			return advancedResponse(`{"RequestId":"request","TotalCount":2,"RecordGroups":{"RecordGroup":[{"GroupId":"42","GroupName":"Web"},{"GroupId":43,"GroupName":"Mail"}]}}`), nil
		case "DescribeDomainRecordInfo":
			zone := "example.org"
			if q.Get("RecordId") == "foreign" {
				zone = "outside.example"
			}
			return advancedResponse(`{"RequestId":"request","Locked":false,"RR":"www","Type":"A","Value":"1.1.1.1","Line":"default","TTL":600,"DomainName":"` + zone + `","RecordId":"` + q.Get("RecordId") + `","GroupId":"42"}`), nil
		case "ChangeRecordGroup":
			if q.Get("RecordIdList") != `["row"]` || q.Get("GroupId") != "43" || q.Get("DomainName") != "example.org" {
				t.Errorf("incorrect group move")
			}
			writes++
		case "SetDNSSLBStatus":
			if q.Get("SubDomain") != "example.org" || q.Get("DomainName") != "example.org" || q.Get("Open") != "true" {
				t.Errorf("incorrect apex weighting")
			}
			writes++
		case "DescribeRecordLogs":
			return advancedResponse(`{"TotalCount":1,"RecordLogs":{"RecordLog":[{"Action":"AddDomainRecord","ActionTime":"2026-10-10 10:00:00","Message":"synthetic-private-payload"}]}}`), nil
		default:
			t.Errorf("unexpected action %q", action)
		}
		return advancedResponse(`{"RequestId":"request"}`), nil
	})
	client, err := ali.NewClient(&api.Config{AccessKeyId: ptr("synthetic-id"), AccessKeySecret: ptr("synthetic-secret"), Endpoint: ptr("alidns.aliyuncs.com"), HttpClient: transport})
	if err != nil {
		t.Fatal(err)
	}
	p := Aliyun{sdk: client}
	g, err := p.BatchGroups(ctx, "example.org")
	if err != nil || len(g) != 2 || g[1].ID != "43" || g[0].Name != "Web" {
		t.Fatal(g, err)
	}
	if group, err := p.BatchGroup(ctx, "example.org", "row"); err != nil || group != "42" {
		t.Fatal(group, err)
	}
	if err := p.SetBatchGroup(ctx, "example.org", "foreign", "43"); !domain.IsRecordNotFoundError(err) {
		t.Fatal(err)
	}
	if err := p.SetBatchGroup(ctx, "example.org", "row", "hidden-group"); err != dns.ErrInvalidDNSRequest {
		t.Fatal(err)
	}
	if err := p.SetBatchGroup(ctx, "example.org", "row", "43"); err != nil {
		t.Fatal(err)
	}
	if err := p.SetWeightRule(ctx, "example.org", dns.WeightRule{Name: "example.org", Type: "A", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	logs, err := p.BatchLogs(ctx, "example.org", 1)
	if err != nil || len(logs.Items) != 1 || logs.Items[0].Action != "AddDomainRecord" {
		t.Fatal(logs, err)
	}
	data, _ := json.Marshal(logs)
	if strings.Contains(string(data), "synthetic-private") || writes != 2 {
		t.Fatal("unexpected result or writes")
	}
}

func TestTencentGroupsAliasesAndScopedLogs(t *testing.T) {
	ctx := t.Context()
	p, err := NewTencent(&domain.Access{Config: map[string]any{"secretId": "synthetic-id", "secretKey": "synthetic-secret"}})
	if err != nil {
		t.Fatal(err)
	}
	writes := 0
	p.sdk.WithHttpTransport(advancedTransport(func(r *http.Request) (*http.Response, error) {
		var q map[string]any
		if err := json.NewDecoder(r.Body).Decode(&q); err != nil {
			t.Fatal(err)
		}
		if q["Domain"] != "example.org" {
			t.Error("unscoped Tencent API call")
		}
		switch r.Header.Get("X-TC-Action") {
		case "DescribeRecord":
			return advancedResponse(`{"Response":{"RecordInfo":{"Id":23,"SubDomain":"www","RecordType":"A","Value":"1.1.1.1","RecordLine":"Default","TTL":600},"RequestId":"request"}}`), nil
		case "DescribeRecordGroupList":
			return advancedResponse(`{"Response":{"GroupList":[{"GroupId":42,"GroupName":"web"}],"RequestId":"request"}}`), nil
		case "DescribeRecordFilterList":
			if q["SubDomain"] != "www" || q["IsExactSubDomain"] != true || q["RecordValue"] != "1.1.1.1" {
				t.Error("unexpected group query")
			}
			return advancedResponse(`{"Response":{"RecordList":[{"RecordId":23}],"RecordCountInfo":{"TotalCount":1},"RequestId":"request"}}`), nil
		case "DescribeDomainAliasList":
			return advancedResponse(`{"Response":{"DomainAliasList":[{"Id":51,"DomainAlias":"alias.example"}],"RequestId":"request"}}`), nil
		case "DeleteDomainAlias":
			if q["DomainAliasId"] != float64(51) {
				t.Error("deleted wrong alias")
			}
			writes++
		case "ModifyRecordToGroup":
			if q["RecordId"] != "23" || q["GroupId"] != float64(42) {
				t.Error("incorrect group write")
			}
			writes++
		case "DescribeDomainLogList":
			return advancedResponse(`{"Response":{"LogList":["2026-10-21 10:20:30 (synthetic-ip) 修改记录 synthetic-data Uin: synthetic-user"],"TotalCount":1,"RequestId":"request"}}`), nil
		default:
			t.Errorf("unexpected Tencent operation %q", r.Header.Get("X-TC-Action"))
		}
		return advancedResponse(`{"Response":{"RequestId":"request"}}`), nil
	}))
	if id, err := p.BatchGroup(ctx, "example.org", "23"); err != nil || id != "42" {
		t.Fatal(id, err)
	}
	if err := p.SetBatchGroup(ctx, "example.org", "23", "42"); err != nil {
		t.Fatal(err)
	}
	if err := p.DeleteDomainAlias(ctx, "example.org", "52"); !domain.IsRecordNotFoundError(err) {
		t.Fatal(err)
	}
	if err := p.DeleteDomainAlias(ctx, "example.org", "51"); err != nil {
		t.Fatal(err)
	}
	logs, err := p.BatchLogs(ctx, "example.org", 1)
	if err != nil || len(logs.Items) != 1 || logs.Items[0].Action != "修改记录" || logs.Items[0].Time != "2026-10-21 10:20:30" || writes != 2 {
		t.Fatal(logs, err, writes)
	}
}

func TestNativeGroupIndexes(t *testing.T) {
	ctx := t.Context()
	groups := []dns.RecordGroup{{ID: "42"}, {ID: "51"}}
	for _, provider := range []string{"Aliyun", "DNSPod"} {
		t.Run(provider, func(t *testing.T) {
			calls := 0
			transport := advancedTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				var group, offset int
				if provider == "Aliyun" {
					q := r.URL.Query()
					if q.Get("Action") != "DescribeDomainRecords" && aliAction(r) != "DescribeDomainRecords" || q.Get("DomainName") != "example.org" || q.Get("PageSize") != "100" {
						t.Fatal("unexpected AliDNS group query")
					}
					group, _ = strconv.Atoi(q.Get("GroupId"))
					page, _ := strconv.Atoi(q.Get("PageNumber"))
					offset = (page - 1) * 100
				} else {
					var in struct {
						Domain                 string
						GroupId, Offset, Limit int
					}
					if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Domain != "example.org" || in.Limit != 100 || r.Header.Get("X-TC-Action") != "DescribeRecordList" {
						t.Fatal("unexpected DNSPod group query", err)
					}
					group = in.GroupId
					offset = in.Offset
				}
				var total, first int
				switch group {
				case 42:
					total = 101
					first = 1000
				case 51:
					total = 1
					first = 2000
				default:
					t.Fatal("missing group filter")
				}
				var rows []map[string]any
				for i := offset; i < min(total, offset+100); i++ {
					if provider == "Aliyun" {
						rows = append(rows, map[string]any{"RecordId": strconv.Itoa(first + i), "DomainName": "example.org"})
					} else {
						rows = append(rows, map[string]any{"RecordId": first + i})
					}
				}
				var out any
				if provider == "Aliyun" {
					out = map[string]any{"TotalCount": total, "PageNumber": offset/100 + 1, "DomainRecords": map[string]any{"Record": rows}}
				} else {
					out = map[string]any{"Response": map[string]any{"RecordCountInfo": map[string]any{"TotalCount": total}, "RecordList": rows, "RequestId": "request"}}
				}
				body, err := json.Marshal(out)
				if err != nil {
					t.Fatal(err)
				}
				return advancedResponse(string(body)), nil
			})
			var index map[string]string
			var err error
			if provider == "Aliyun" {
				client, e := ali.NewClient(&api.Config{AccessKeyId: ptr("synthetic-id"), AccessKeySecret: ptr("synthetic-secret"), Endpoint: ptr("alidns.aliyuncs.com"), HttpClient: transport})
				if e != nil {
					t.Fatal(e)
				}
				index, err = (&Aliyun{sdk: client}).BatchGroupIndex(ctx, "example.org", groups)
			} else {
				p, e := NewTencent(&domain.Access{Config: map[string]any{"secretId": "synthetic-id", "secretKey": "synthetic-secret"}})
				if e != nil {
					t.Fatal(e)
				}
				p.sdk.WithHttpTransport(transport)
				index, err = p.BatchGroupIndex(ctx, "example.org", groups)
			}
			if err != nil || len(index) != 102 || index["1100"] != "42" || index["2000"] != "51" || calls != 3 {
				t.Fatalf("incomplete group index, records=%d calls=%d err=%v", len(index), calls, err)
			}
		})
	}
}
func TestGroupIndexRejectsIncompleteAndAmbiguousPages(t *testing.T) {
	full := make([]string, 100)
	for i := range full {
		full[i] = strconv.Itoa(i + 1)
	}
	for _, tc := range []struct {
		name   string
		groups []dns.RecordGroup
		pages  []groupPage
	}{
		{"short page", []dns.RecordGroup{{ID: "1"}}, []groupPage{{total: 2, ids: []string{"1"}}}},
		{"repeated row", []dns.RecordGroup{{ID: "1"}}, []groupPage{{total: 2, ids: []string{"1", "1"}}}},
		{"changing count", []dns.RecordGroup{{ID: "1"}}, []groupPage{{total: 101, ids: full}, {total: 100}}},
		{"foreign membership", []dns.RecordGroup{{ID: "1"}, {ID: "2"}}, []groupPage{{total: 1, ids: []string{"a"}}, {total: 1, ids: []string{"a"}}}},
		{"duplicate groups", []dns.RecordGroup{{ID: "1"}, {ID: "1"}}, nil},
		{"oversized group", []dns.RecordGroup{{ID: "1"}}, []groupPage{{total: groupIndexMaxRecords + 1}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			index, err := recordGroupIndex(t.Context(), tc.groups, "DNSPod", func(string, int) (groupPage, error) { row := tc.pages[calls]; calls++; return row, nil })
			if index != nil || err == nil || calls != len(tc.pages) {
				t.Fatal(index, err, calls)
			}
		})
	}
}
