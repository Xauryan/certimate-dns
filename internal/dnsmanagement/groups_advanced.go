package dnsmanagement

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
	"unicode"

	api "github.com/alibabacloud-go/darabonba-openapi/v2/utils"
	"github.com/alibabacloud-go/tea/dara"
	dns "github.com/certimate-go/certimate/pkg/core/dnsmanagement"
	ali "github.com/go-acme/alidns-20150109/v5/client"
	tc "github.com/go-acme/tencentclouddnspod/v20210323"
	tcerr "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
)

// The generated AliDNS client omits these two RPCs. Use its configured transport,
// credentials, context and RPC signer with the same fixed API version.
func (p *Aliyun) groupRPC(ctx context.Context, action string, query map[string]*string, body any) error {
	params := &api.Params{Action: &action, Version: ptr("2015-01-09"), Protocol: ptr("HTTPS"), Pathname: ptr("/"), Method: ptr("POST"), AuthType: ptr("AK"), Style: ptr("RPC"), ReqBodyType: ptr("formData"), BodyType: ptr("json")}
	out, err := p.sdk.CallApiWithCtx(ctx, params, &api.OpenApiRequest{Query: query}, &dara.RuntimeOptions{})
	if err != nil || out["body"] == nil || dara.Convert(out["body"], body) != nil {
		return providerError("Aliyun")
	}
	return nil
}

func (p *Aliyun) BatchGroups(ctx context.Context, zone string) ([]dns.RecordGroup, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	rows := []dns.RecordGroup{}
	for page := 1; page <= 100; page++ {
		var b struct {
			RequestID string `json:"RequestId"`
			Total     int    `json:"TotalCount"`
			Groups    struct {
				Rows []struct {
					ID   json.RawMessage `json:"GroupId"`
					Name string          `json:"GroupName"`
				} `json:"RecordGroup"`
			} `json:"RecordGroups"`
		}
		if err := p.groupRPC(ctx, "DescribeRecordGroups", map[string]*string{"DomainName": &z, "PageSize": ptr("100"), "PageNumber": ptr(strconv.Itoa(page))}, &b); err != nil {
			return nil, err
		}
		if b.RequestID == "" {
			return nil, providerError("Aliyun")
		}
		for _, g := range b.Groups.Rows {
			id, err := parseGroupID(g.ID)
			if err != nil {
				return nil, providerError("Aliyun")
			}
			rows = append(rows, dns.RecordGroup{ID: id, Name: g.Name})
		}
		if len(rows) == b.Total {
			return rows, nil
		}
		if len(b.Groups.Rows) == 0 || len(rows) > b.Total {
			return nil, providerError("Aliyun")
		}
	}
	return nil, providerError("Aliyun")
}

// Some AliDNS versions return numeric group IDs, others quote the ID.
func parseGroupID(raw json.RawMessage) (string, error) {
	var id string
	if len(raw) > 0 && raw[0] == '"' {
		if err := json.Unmarshal(raw, &id); err != nil {
			return "", err
		}
	} else {
		if _, err := strconv.ParseUint(string(raw), 10, 64); err != nil {
			return "", err
		}
		id = string(raw)
	}
	if id == "" || len(id) > 128 || strings.IndexFunc(id, unicode.IsControl) >= 0 {
		return "", dns.ErrInvalidDNSRequest
	}
	return id, nil
}
func containsGroup(groups []dns.RecordGroup, id string) bool {
	for _, g := range groups {
		if g.ID == id {
			return true
		}
	}
	return false
}
func (p *Aliyun) BatchGroup(ctx context.Context, zone, id string) (string, error) {
	r, err := p.record(ctx, zone, id)
	if err != nil {
		return "", err
	}
	return val(r.GroupId), nil
}
func (p *Aliyun) SetBatchGroup(ctx context.Context, zone, id, group string) error {
	r, err := p.writableRecord(ctx, zone, id)
	if err != nil {
		return err
	}
	groups, err := p.BatchGroups(ctx, zone)
	if err != nil {
		return err
	}
	if !containsGroup(groups, group) {
		return dns.ErrInvalidDNSRequest
	}
	list, err := json.Marshal([]string{id})
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	var b struct {
		RequestID string `json:"RequestId"`
	}
	if err := p.groupRPC(ctx, "ChangeRecordGroup", map[string]*string{"DomainName": r.DomainName, "RecordIdList": ptr(string(list)), "GroupId": &group}, &b); err != nil {
		return err
	}
	if b.RequestID == "" {
		return providerError("Aliyun")
	}
	return nil
}
func (p *Aliyun) BatchLogs(ctx context.Context, zone string, page int) (*dns.DNSPage[dns.RecordLog], error) {
	if page < 1 || page > 1000000 {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	r, err := ali.DescribeRecordLogsWithContext(ctx, p.sdk, &ali.DescribeRecordLogsRequest{DomainName: &z, PageNumber: ptr(int64(page)), PageSize: ptr(int64(dns.DNSPageSize))}, &dara.RuntimeOptions{})
	if err != nil || r == nil || r.Body == nil {
		return nil, providerError("Aliyun")
	}
	out := newPage[dns.RecordLog](page, int(val(r.Body.TotalCount)))
	if r.Body.RecordLogs != nil {
		for _, row := range r.Body.RecordLogs.RecordLog {
			if row != nil {
				out.Items = append(out.Items, dns.RecordLog{Time: val(row.ActionTime), Action: val(row.Action)})
			}
		}
	}
	return out, nil
}
func (p *Tencent) BatchGroups(ctx context.Context, zone string) ([]dns.RecordGroup, error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	rows := []dns.RecordGroup{}
	for page := 0; page < 100; page++ {
		req := tc.NewDescribeRecordGroupListRequest()
		req.Domain = &z
		req.Offset = ptr(uint64(page * 100))
		req.Limit = ptr(uint64(100))
		r, err := tc.DescribeRecordGroupListWithContext(ctx, p.sdk, req)
		if err != nil || r == nil || r.Response == nil {
			return nil, providerError("DNSPod")
		}
		for _, g := range r.Response.GroupList {
			if g == nil || g.GroupId == nil {
				return nil, providerError("DNSPod")
			}
			rows = append(rows, dns.RecordGroup{ID: strconv.FormatUint(*g.GroupId, 10), Name: val(g.GroupName)})
		}
		if len(r.Response.GroupList) < 100 {
			return rows, nil
		}
	}
	return nil, providerError("DNSPod")
}
func (p *Tencent) BatchGroup(ctx context.Context, zone, id string) (string, error) {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return "", err
	}
	info, err := p.advancedRecord(ctx, z, n)
	if err != nil {
		return "", err
	}
	groups, err := p.BatchGroups(ctx, z)
	if err != nil {
		return "", err
	}
	// DNSPod's detail endpoint has no group ID. Restrict each candidate group
	// query to the exact name, type and value, and confirm the provider record ID.
	for _, g := range groups {
		group, err := strconv.ParseUint(g.ID, 10, 64)
		if err != nil {
			return "", providerError("DNSPod")
		}
		req := tc.NewDescribeRecordFilterListRequest()
		req.Domain = &z
		req.GroupId = []*uint64{&group}
		req.SubDomain = info.SubDomain
		req.IsExactSubDomain = ptr(true)
		req.RecordValue = info.Value
		req.RecordType = []*string{info.RecordType}
		req.Limit = ptr(uint64(3000))
		r, err := tc.DescribeRecordFilterListWithContext(ctx, p.sdk, req)
		var sdkErr *tcerr.TencentCloudSDKError
		if errors.As(err, &sdkErr) && sdkErr.Code == "ResourceNotFound.NoDataOfRecord" {
			continue
		}
		if err != nil || r == nil || r.Response == nil || r.Response.RecordCountInfo == nil {
			return "", providerError("DNSPod")
		}
		for _, row := range r.Response.RecordList {
			if row != nil && val(row.RecordId) == n {
				return g.ID, nil
			}
		}
		if int(val(r.Response.RecordCountInfo.TotalCount)) > len(r.Response.RecordList) {
			return "", providerError("DNSPod")
		}
	}
	return "", nil
}
func (p *Tencent) SetBatchGroup(ctx context.Context, zone, id, group string) error {
	z, n, err := recordKey(zone, id)
	if err != nil {
		return err
	}
	g, err := strconv.ParseUint(group, 10, 64)
	if err != nil {
		return dns.ErrInvalidDNSRequest
	}
	if _, err = p.writableRecord(ctx, z, n); err != nil {
		return err
	}
	groups, err := p.BatchGroups(ctx, z)
	if err != nil {
		return err
	}
	if !containsGroup(groups, group) {
		return dns.ErrInvalidDNSRequest
	}
	req := tc.NewModifyRecordToGroupRequest()
	req.Domain = &z
	req.RecordId = &id
	req.GroupId = &g
	r, err := tc.ModifyRecordToGroupWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil || val(r.Response.RequestId) == "" {
		return providerError("DNSPod")
	}
	return nil
}
func (p *Tencent) BatchLogs(ctx context.Context, zone string, page int) (*dns.DNSPage[dns.RecordLog], error) {
	if page < 1 || page > 1000000 {
		return nil, dns.ErrInvalidDNSRequest
	}
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	req := tc.NewDescribeDomainLogListRequest()
	req.Domain = &z
	req.Offset = ptr(uint64((page - 1) * dns.DNSPageSize))
	req.Limit = ptr(uint64(dns.DNSPageSize))
	r, err := tc.DescribeDomainLogListWithContext(ctx, p.sdk, req)
	if err != nil || r == nil || r.Response == nil {
		return nil, providerError("DNSPod")
	}
	out := newPage[dns.RecordLog](page, int(val(r.Response.TotalCount)))
	for _, line := range r.Response.LogList {
		if line != nil {
			out.Items = append(out.Items, publicTencentLog(*line))
		}
	}
	return out, nil
}
func publicTencentLog(line string) dns.RecordLog {
	// DNSPod embeds client IPs, account IDs and record contents in free text.
	// Return only a parsed timestamp and a recognized operation.
	stamp, rest, _ := strings.Cut(line, "(")
	_, message, _ := strings.Cut(rest, ")")
	row := dns.RecordLog{Action: "DNS change"}
	if ts, err := time.Parse("2006-01-02 15:04:05", strings.TrimSpace(stamp)); err == nil {
		row.Time = ts.Format("2006-01-02 15:04:05")
	}
	for _, action := range []string{"添加记录", "修改记录", "删除记录", "暂停记录", "启用记录", "添加解析", "修改解析", "删除解析", "Added record", "Modified record", "Deleted record"} {
		if strings.HasPrefix(strings.TrimSpace(message), action) {
			row.Action = action
			break
		}
	}
	return row
}

// The same record bound applies to the zone inventory used for an archive.
const groupIndexMaxRecords = 20000
const groupIndexPageSize = 100

type groupPage struct {
	ids   []string
	total int
}

// Build only complete indexes. An omitted ID then denotes no membership in
// the requested groups, including when the caller selected just one group.
func recordGroupIndex(ctx context.Context, groups []dns.RecordGroup, provider string, fetch func(id string, offset int) (groupPage, error)) (map[string]string, error) {
	if len(groups) > 10000 {
		return nil, providerError(provider)
	}
	seen := make(map[string]bool, len(groups))
	for _, g := range groups {
		if g.ID == "" || len(g.ID) > 128 || seen[g.ID] {
			return nil, providerError(provider)
		}
		seen[g.ID] = true
	}
	index := make(map[string]string)
	for _, g := range groups {
		expected := -1
		for offset := 0; ; offset += groupIndexPageSize {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			page, err := fetch(g.ID, offset)
			if err != nil {
				return nil, err
			}
			if page.total < 0 || page.total > groupIndexMaxRecords || (expected >= 0 && expected != page.total) || offset > page.total || len(page.ids) != min(groupIndexPageSize, page.total-offset) || len(index)+len(page.ids) > groupIndexMaxRecords {
				return nil, providerError(provider)
			}
			expected = page.total
			for _, id := range page.ids {
				if id == "" || index[id] != "" {
					return nil, providerError(provider)
				}
				index[id] = g.ID
			}
			if offset+len(page.ids) == expected {
				break
			}
		}
	}
	return index, nil
}

func (p *Aliyun) BatchGroupIndex(ctx context.Context, zone string, groups []dns.RecordGroup) (map[string]string, error) {
	z, err := p.zone(ctx, zone)
	if err != nil {
		return nil, err
	}
	return recordGroupIndex(ctx, groups, "Aliyun", func(group string, offset int) (groupPage, error) {
		id, err := strconv.ParseInt(group, 10, 64)
		// The special all-groups selector cannot describe membership.
		if err != nil || id < -1 || strconv.FormatInt(id, 10) != group {
			return groupPage{}, dns.ErrInvalidDNSRequest
		}
		page := int64(offset/groupIndexPageSize + 1)
		req := &ali.DescribeDomainRecordsRequest{DomainName: &z, GroupId: &id, PageNumber: &page, PageSize: ptr(int64(groupIndexPageSize))}
		r, err := ali.DescribeDomainRecordsWithContext(ctx, p.sdk, req, &dara.RuntimeOptions{})
		if err != nil || r == nil || r.Body == nil || r.Body.TotalCount == nil || r.Body.PageNumber == nil || *r.Body.PageNumber != page {
			return groupPage{}, providerError("Aliyun")
		}
		out := groupPage{total: int(*r.Body.TotalCount)}
		if r.Body.DomainRecords == nil {
			return out, nil
		}
		for _, record := range r.Body.DomainRecords.Record {
			if record == nil || !strings.EqualFold(val(record.DomainName), z) {
				return groupPage{}, providerError("Aliyun")
			}
			out.ids = append(out.ids, val(record.RecordId))
		}
		return out, nil
	})
}

func (p *Tencent) BatchGroupIndex(ctx context.Context, zone string, groups []dns.RecordGroup) (map[string]string, error) {
	z, err := zoneName(zone)
	if err != nil {
		return nil, err
	}
	return recordGroupIndex(ctx, groups, "DNSPod", func(group string, offset int) (groupPage, error) {
		id, err := strconv.ParseUint(group, 10, 64)
		if err != nil || strconv.FormatUint(id, 10) != group {
			return groupPage{}, dns.ErrInvalidDNSRequest
		}
		req := tc.NewDescribeRecordListRequest()
		req.Domain = &z
		req.GroupId = &id
		req.Offset = ptr(uint64(offset))
		req.Limit = ptr(uint64(groupIndexPageSize))
		r, err := tc.DescribeRecordListWithContext(ctx, p.sdk, req)
		var sdkErr *tcerr.TencentCloudSDKError
		if errors.As(err, &sdkErr) && sdkErr.Code == "ResourceNotFound.NoDataOfRecord" {
			return groupPage{}, nil
		}
		if err != nil || r == nil || r.Response == nil || r.Response.RecordCountInfo == nil || r.Response.RecordCountInfo.TotalCount == nil {
			return groupPage{}, providerError("DNSPod")
		}
		count := *r.Response.RecordCountInfo.TotalCount
		if count > groupIndexMaxRecords {
			return groupPage{}, providerError("DNSPod")
		}
		out := groupPage{total: int(count)}
		for _, record := range r.Response.RecordList {
			if record == nil || val(record.RecordId) == 0 {
				return groupPage{}, providerError("DNSPod")
			}
			out.ids = append(out.ids, strconv.FormatUint(*record.RecordId, 10))
		}
		return out, nil
	})
}
