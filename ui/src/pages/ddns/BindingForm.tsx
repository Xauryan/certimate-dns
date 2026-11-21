import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Alert, Button, Form, Input, Pagination, Select } from "antd";

import { type DNSRecord, type Page } from "@/api/dns";
import { dnsAccountProviderLabels } from "@/domain/dnsAccount";
import { type Account, type Zone, useCatalog } from "@/pages/dnscatalog/catalog";
import { type BindingTarget, type NetworkInterface } from "./model";

type Props = {
  interfaces: NetworkInterface[];
  busy: boolean;
  onBind: (target: BindingTarget) => void;
};

export default function BindingForm({ interfaces, busy, onBind }: Props) {
  const { t } = useTranslation();
  const [account, setAccount] = useState<Account>();
  const [zone, setZone] = useState<Zone>();
  const [recordId, setRecordId] = useState<string>();
  const [interfaceName, setInterfaceName] = useState<string>();
  const [zonePage, setZonePage] = useState(1);
  const [recordPage, setRecordPage] = useState(1);
  const [search, setSearch] = useState("");
  const accounts = useCatalog<Account[]>("/accounts", 0);
  const zones = useCatalog<{ items: Zone[]; total: number }>(
    account ? "/domains?" + new URLSearchParams({ accessId: account.id, page: String(zonePage) }) : undefined,
    0
  );
  const recordQuery = new URLSearchParams({ page: String(recordPage), name: search });
  const records = useCatalog<Page<DNSRecord>>(
    account && zone
      ? "/api/dns/" + [account.provider, account.id].map(encodeURIComponent).join("/") + "/zones/" + encodeURIComponent(zone.zoneId) + "/records?" + recordQuery
      : undefined,
    0,
    true
  );
  const error = accounts?.error || zones?.error || records?.error;
  const writable = records?.data?.result?.filter((record) => !record.readOnly && ["A", "AAAA"].includes(record.type)) ?? [];
  const selected = writable.some((record) => record.id === recordId);

  function chooseZone(next?: Zone) {
    setZone(next);
    setRecordId(undefined);
    setRecordPage(1);
    setSearch("");
  }

  return (
    <Form
      layout="vertical"
      disabled={busy}
      onFinish={() => {
        if (account && zone && selected && recordId && interfaceName && interfaces.some((iface) => iface.name === interfaceName)) {
          onBind({ provider: account.provider, accessId: account.id, zoneId: zone.zoneId, recordId, interfaceName });
        }
      }}
    >
      {error && <Alert className="mb-4" type="error" title={error} showIcon />}
      <Form.Item label={t("dns.account")} required>
        <Select
          aria-label={t("dns.account")}
          showSearch={{ optionFilterProp: "label" }}
          value={account?.id}
          loading={!accounts}
          options={accounts?.data
            ?.filter((item) => item.enabled && item.provider !== "spaceship")
            .map((item) => ({
              value: item.id,
              label: item.name + " · " + t(dnsAccountProviderLabels.get(item.provider) ?? item.provider),
            }))}
          onChange={(id) => {
            setAccount(accounts?.data?.find((item) => item.id === id));
            setZonePage(1);
            chooseZone();
          }}
        />
      </Form.Item>
      {account && (
        <Form.Item label={t("dns.zone")} required>
          <Select
            aria-label={t("dns.zone")}
            showSearch={{ optionFilterProp: "label" }}
            value={zone?.id}
            loading={!zones}
            options={zones?.data?.items.filter((item) => item.present && item.enabled).map((item) => ({ value: item.id, label: item.name }))}
            onChange={(id) => chooseZone(zones?.data?.items.find((item) => item.id === id))}
          />
          <Pagination
            className="mt-2"
            size="small"
            hideOnSinglePage
            showSizeChanger={false}
            current={zonePage}
            pageSize={25}
            total={zones?.data?.total ?? 0}
            onChange={(page) => {
              setZonePage(page);
              chooseZone();
            }}
          />
        </Form.Item>
      )}
      {zone && (
        <Form.Item label={t("ddns.record")} required>
          <Input.Search
            key={zone.id}
            className="mb-2"
            aria-label={t("dns.search")}
            placeholder={t("dns.search")}
            allowClear
            onSearch={(value) => {
              setSearch(value.trim());
              setRecordPage(1);
              setRecordId(undefined);
            }}
          />
          <Select
            aria-label={t("ddns.record")}
            value={recordId}
            loading={!records}
            options={writable.map((item) => ({ value: item.id, label: [item.name, item.type, item.content, item.line].filter(Boolean).join(" · ") }))}
            onChange={setRecordId}
          />
          <Pagination
            className="mt-2"
            size="small"
            hideOnSinglePage
            showSizeChanger={false}
            current={recordPage}
            pageSize={20}
            total={records?.data?.result_info.total_count ?? 0}
            onChange={(page) => {
              setRecordPage(page);
              setRecordId(undefined);
            }}
          />
        </Form.Item>
      )}
      <Form.Item label={t("ddns.interface")} required>
        <Select
          aria-label={t("ddns.interface")}
          value={interfaceName}
          options={interfaces.map((iface) => ({ value: iface.name, label: [iface.name, iface.mac].filter(Boolean).join(" · ") }))}
          onChange={setInterfaceName}
        />
      </Form.Item>
      <Button type="primary" htmlType="submit" loading={busy} disabled={!selected || !interfaces.some((iface) => iface.name === interfaceName)}>
        {t("ddns.bind")}
      </Button>
    </Form>
  );
}
