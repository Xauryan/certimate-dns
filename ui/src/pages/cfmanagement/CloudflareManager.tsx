import { useEffect, useState } from "react";
import { Alert, Select, Space, Tabs, Typography } from "antd";
import { Link } from "react-router-dom";
import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";
import { ScopeSelect, LoadError, useLabel } from "./shared";
import Hostnames from "./Hostnames";
import Tunnels from "./Tunnels";

function Scopes({ access }: { access: string }) {
  const l = useLabel();
  const base = "/api/cloudflare/" + encodeURIComponent(access);
  const [zone, setZone] = useState<string>();
  const [account, setAccount] = useState<string>();
  return (
    <Tabs
      destroyOnHidden
      items={[
        {
          key: "saas",
          label: "Cloudflare for SaaS",
          children: (
            <div className="flex flex-col gap-4">
              <ScopeSelect
                url={"/api/dns/cloudflare/" + encodeURIComponent(access) + "/zones"}
                label={l("Select zone", "选择域名")}
                value={zone}
                choose={setZone}
              />
              {zone && <Hostnames key={zone} base={base + "/zones/" + encodeURIComponent(zone)} />}
            </div>
          ),
        },
        {
          key: "tunnels",
          label: "Cloudflare Tunnel",
          children: (
            <div className="flex flex-col gap-4">
              <ScopeSelect url={base + "/accounts"} label={l("Select Cloudflare account", "选择 Cloudflare 账户")} value={account} choose={setAccount} />
              {account && (
                <Tunnels
                  key={account}
                  zonesUrl={"/api/dns/cloudflare/" + encodeURIComponent(access) + "/zones"}
                  base={base + "/accounts/" + encodeURIComponent(account) + "/tunnels"}
                />
              )}
            </div>
          ),
        },
      ]}
    />
  );
}

export default function CloudflareManager() {
  const l = useLabel();
  const [accesses, setAccesses] = useState<{ value: string; label: string }[]>();
  const [access, setAccess] = useState<string>();
  const [error, setError] = useState("");
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    dnsRequest<{ id: string; name: string; provider: string; enabled: boolean }[]>("/api/dns-catalog/accounts")
      .then((items) => {
        if (!active) return;
        const options = items.filter((i) => i.provider === "cloudflare" && i.enabled).map((i) => ({ value: i.id, label: i.name }));
        setAccesses(options);
        setAccess(options[0]?.value);
        setError("");
      })
      .catch((e) => {
        if (active) setError(unwrapErrMsg(e));
      });
    return () => {
      active = false;
    };
  }, [revision]);
  const title = l("Cloudflare management", "Cloudflare 管理");
  return (
    <main className="flex flex-col gap-4 p-4 md:p-6">
      <Typography.Title level={3}>{title}</Typography.Title>
      <Space wrap>
        <Select
          aria-label={l("Cloudflare credential", "Cloudflare 授权")}
          style={{ minWidth: 220 }}
          value={access}
          options={accesses}
          onChange={setAccess}
          loading={!accesses && !error}
        />
        <Link to="/accesses">{l("Manage credentials", "管理授权")}</Link>
      </Space>
      {error && <LoadError text={error} retry={() => setRevision((v) => v + 1)} />}
      {accesses?.length === 0 && <Alert type="info" title={l("Add a Cloudflare API token in credentials.", "请先在授权管理中添加 Cloudflare API 令牌。")} />}
      {access && <Scopes key={access} access={access} />}
    </main>
  );
}
