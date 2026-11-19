import { useEffect, useState } from "react";
import { Alert, Form, Input, Pagination, Select } from "antd";
import { type DNSRecord, type Page, dnsRequest } from "@/api/dns";
import { type Account, type Zone, useCatalog } from "@/pages/dnscatalog/catalog";
import { unwrapErrMsg } from "@/utils/error";
import { type Label, type Target } from "./types";

function usePage<T>(url: string) {
  const [result, setResult] = useState<{ url: string; page?: Page<T>; error?: string }>();
  useEffect(() => {
    let current = true;
    if (url)
      dnsRequest<Page<T>>(url).then(
        (page) => {
          if (current) setResult({ url, page });
        },
        (e) => {
          if (current) setResult({ url, error: unwrapErrMsg(e) });
        }
      );
    return () => {
      current = false;
    };
  }, [url]);
  return result?.url === url ? result : undefined;
}

export default function TargetPicker({ label, onChange }: { label: Label; onChange: (target?: Target, primary?: string, provider?: string) => void }) {
  const [account, setAccount] = useState<Account>();
  const [zone, setZone] = useState<Zone>();
  const [record, setRecord] = useState("");
  const [name, setName] = useState("");
  const [search, setSearch] = useState("");
  const [zp, setZp] = useState(1);
  const [rp, setRp] = useState(1);
  const root = account ? "/api/dns/" + [account.provider, account.id].map(encodeURIComponent).join("/") + "/zones" : "";
  const accounts = useCatalog<Account[]>("/accounts", 0);
  const zones = useCatalog<{ items: Zone[]; total: number }>("/domains?" + new URLSearchParams({ accessId: account?.id || "", page: String(zp) }), 0);
  const records = usePage<DNSRecord>(
    root && zone ? root + "/" + encodeURIComponent(zone.zoneId) + "/records?" + new URLSearchParams({ page: String(rp), name: search }) : ""
  );
  const error = accounts?.error || zones?.error || records?.error;
  function clearRecord() {
    setRecord("");
    onChange();
    setRp(1);
    setName("");
    setSearch("");
  }
  return (
    <>
      {error && <Alert type="error" title={error} />}
      <Form.Item label={label("DNS 账户", "DNS account")} required>
        <Select
          showSearch
          optionFilterProp="label"
          value={account?.id}
          options={accounts?.data?.filter((a) => a.enabled).map((a) => ({ value: a.id, label: a.name + " · " + a.provider }))}
          onChange={(id) => {
            setAccount(accounts?.data?.find((a) => a.id === id));
            setZone(undefined);
            setZp(1);
            clearRecord();
          }}
        />
      </Form.Item>
      {account && (
        <Form.Item label={label("域名", "Zone")} required>
          <Select
            showSearch
            optionFilterProp="label"
            loading={!zones}
            value={zone?.id}
            options={zones?.data?.items.filter((z) => z.present && z.enabled).map((z) => ({ value: z.id, label: z.name }))}
            onChange={(id) => {
              setZone(zones?.data?.items.find((z) => z.id === id));
              clearRecord();
            }}
          />
          <Pagination size="small" hideOnSinglePage showSizeChanger={false} current={zp} pageSize={25} total={zones?.data?.total} onChange={setZp} />
        </Form.Item>
      )}
      {zone && (
        <Form.Item label={label("记录", "Record")} required>
          <Input.Search
            value={name}
            allowClear
            placeholder={label("按记录名查找", "Search by record name")}
            onChange={(e) => setName(e.target.value)}
            onSearch={(v) => {
              setSearch(v.trim());
              setRp(1);
            }}
          />
          <Select
            loading={!records}
            value={record || undefined}
            options={records?.page?.result
              .filter((r) => !r.readOnly && ["A", "AAAA", "CNAME"].includes(r.type))
              .map((r) => ({ value: r.id, label: [r.name, r.type, r.content, r.line].filter(Boolean).join(" · ") }))}
            onChange={(id) => {
              const r = records?.page?.result.find((r) => r.id === id);
              if (r && account) {
                setRecord(r.id);
                let owner = r.name;
                if (account.provider === "cloudflare" && owner.toLowerCase().endsWith("_pause." + zone.name.toLowerCase())) {
                  const prefix = owner.slice(0, -("_pause." + zone.name).length);
                  owner = prefix === "__root__" ? zone.name : prefix + "." + zone.name;
                }
                onChange({ accountId: account.id, zoneId: zone.zoneId, recordId: r.id, name: owner, type: r.type }, r.content, account.provider);
              }
            }}
          />
          <Pagination
            size="small"
            hideOnSinglePage
            showSizeChanger={false}
            current={rp}
            pageSize={20}
            total={records?.page?.result_info.total_count}
            onChange={setRp}
          />
        </Form.Item>
      )}
    </>
  );
}
