import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, useNavigate, useSearchParams } from "react-router-dom";
import { useRequest } from "ahooks";
import { Alert, Button, Space, Table, Tabs, Typography } from "antd";

import type { RecordModel } from "pocketbase";
import { dnsRequest } from "@/api/dns";
import { Records } from "@/pages/dns/DNSManager";

import DNSMemberLogin from "@/pages/dnsidentity/DNSMemberLogin";
import MemberSecurity from "@/pages/dnsidentity/MemberSecurity";
import DNSInterfaceKeys from "@/pages/dnsinterfaces/DNSInterfaceKeys";
import { getPocketBase } from "@/repository/_pocketbase";
import { unwrapErrMsg } from "@/utils/error";
import MemberPassword from "./MemberPassword";
import QuickLink from "./QuickLink";

interface MemberZone {
  id: string;
  provider: string;
  accessId: string;
  zoneId: string;
  name: string;
  status: string;
  canWrite: boolean;
  quickLoginEnabled: boolean;
}

function MyZones({ delegated }: { delegated: boolean }) {
  const { t } = useTranslation();
  const [page, setPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [zone, setZone] = useState<MemberZone>();

  const {
    data: result,
    loading,
    error,
  } = useRequest(() => dnsRequest<{ items: MemberZone[]; total: number }>(`/api/dns-member/zones?page=${page}&perPage=20`), { refreshDeps: [page, revision] });

  if (zone) {
    return (
      <Records
        provider={zone.provider}
        base={`/api/dns/${encodeURIComponent(zone.provider)}/${encodeURIComponent(zone.accessId)}`}
        zone={{ id: zone.zoneId, name: zone.name, status: zone.status }}
        canWrite={zone.canWrite}
        back={() => {
          setZone(undefined);
          setRevision((v) => v + 1);
        }}
      />
    );
  }
  return (
    <>
      <Space>
        <Typography.Title level={4} style={{ margin: 0 }}>
          {t("dnsauth.memberZones")}
        </Typography.Title>
        <Button onClick={() => setRevision((v) => v + 1)}>{t("dns.refresh")}</Button>
      </Space>
      {error && <Alert showIcon type="error" title={unwrapErrMsg(error)} />}
      <Table<MemberZone>
        rowKey="id"
        dataSource={loading || error ? [] : result?.items}
        loading={loading}
        pagination={{
          current: page,
          pageSize: 20,
          total: result?.total ?? 0,
          showSizeChanger: false,
          onChange: setPage,
        }}
        columns={[
          {
            title: t("dns.zone"),
            render: (_, row) => (
              <Button type="link" onClick={() => setZone(row)}>
                {row.name}
              </Button>
            ),
          },
          { title: t("dnsauth.provider"), dataIndex: "provider" },
          {
            title: t("dns.actions"),
            hidden: delegated,
            render: (_, row) => row.quickLoginEnabled && <QuickLink id={row.id} name={row.name} canWrite={row.canWrite} />,
          },
          { title: t("dnsauth.role"), render: (_, row) => t(row.canWrite ? "dnsauth.editor" : "dnsauth.reader") },
        ]}
      />
    </>
  );
}

export default function DNSMember() {
  const { t } = useTranslation();
  const auth = getPocketBase().authStore;
  const [record, setRecord] = useState(auth.isValid ? auth.record : null);
  useEffect(() => auth.onChange(() => setRecord(auth.isValid ? auth.record : null), true), [auth]);
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const ticket = params.get("ticket");
  if (ticket) {
    const redeem = async () => {
      setBusy(true);
      setError("");
      try {
        const data = await dnsRequest<{ token: string; record: RecordModel }>("/api/dns-member/redeem", "POST", { ticket });
        auth.save(data.token, data.record);
        navigate("/dns-member", { replace: true });
      } catch (err) {
        setError(unwrapErrMsg(err));
      } finally {
        setBusy(false);
      }
    };
    return (
      <main className="mx-auto flex max-w-lg flex-col gap-4 p-6">
        <Typography.Title level={3}>{t("dnsauth.quickLink")}</Typography.Title>
        <Typography.Text>{t(record ? "dnsauth.replaceSession" : "dnsauth.openZone")}</Typography.Text>
        {error && <Alert type="error" title={error} />}
        <Space>
          <Button type="primary" loading={busy} onClick={redeem}>
            {t("dnsauth.openLink")}
          </Button>
          <Button onClick={() => navigate("/dns-member", { replace: true })}>{t("dnsauth.cancel")}</Button>
        </Space>
      </main>
    );
  }
  if (record && auth.isSuperuser) return <Navigate to="/dns-permissions" replace />;
  const delegated = record?.collectionName === "dns_zone_sessions";
  if (!record || (!delegated && record.collectionName !== "dns_members")) return <DNSMemberLogin />;

  return (
    <main className="mx-auto flex max-w-6xl flex-col gap-6 p-4 md:p-8">
      <header className="flex flex-wrap items-center justify-between gap-4">
        <Typography.Title level={3} style={{ margin: 0 }}>
          {t("dnsauth.portal")}
        </Typography.Title>
        <Space>
          {!delegated && <Typography.Text>{record.email}</Typography.Text>}
          {!delegated && <MemberPassword />}
          <Button onClick={() => auth.clear()}>{t("common.menu.logout")}</Button>
        </Space>
      </header>
      {delegated ? (
        <MyZones key={record.id} delegated />
      ) : (
        <Tabs
          key={record.id}
          items={[
            { key: "zones", label: t("dnsauth.memberZones"), children: <MyZones delegated={false} /> },
            { key: "keys", label: t("dnsauth.interfaceKeys"), children: <DNSInterfaceKeys /> },
            { key: "security", label: t("dnsauth.security"), children: <MemberSecurity /> },
          ]}
        />
      )}
    </main>
  );
}
