import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";
import { useRequest } from "ahooks";
import { Alert, Button, Card, Skeleton, Tag } from "antd";

import { dnsRequest } from "@/api/dns";

type OptimizationResult = { at: number; status: "success" | "failed" } & (
  { catalogId?: undefined } | { catalogId: string; provider: string; access: string; zone: string }
);

type Summary = {
  domains: number;
  scheduled: number;
  failover: { total: number; active: number; primary: number; backup: number; heartbeat: number | null; running: boolean | null };
  optimization: {
    total: number;
    active: number;
    succeeded: number;
    failed: number;
    heartbeat: number | null;
    last: OptimizationResult | null;
  };
  orders: { total: number; issued: number; failed: number; expiring: number; expired: number };
  deployments: { total: number; pending: number; succeeded: number; failed: number };
};

function SummaryCard({ title, to, total, entries }: { title: string; to: string; total: number; entries: [string, React.ReactNode, string?][] }) {
  return (
    <Card size="small" title={<Link to={to}>{title}</Link>} extra={<span className="font-semibold tabular-nums">{total}</span>}>
      <dl className="m-0 flex flex-col gap-1.5 text-sm">
        {entries.map(([label, value, link]) => (
          <div className="flex flex-wrap items-baseline justify-between gap-x-2" key={label}>
            <dt>{link ? <Link to={link}>{label}</Link> : label}</dt>
            <dd className="m-0 text-end tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
    </Card>
  );
}

export default function DNSOverview() {
  const { t, i18n } = useTranslation();
  const { data, error, loading, refresh } = useRequest(() => dnsRequest<Summary>("/api/dns-overview"));
  const text = (key: string) => t(`dashboard.dns_overview.${key}`);
  const date = (stamp: number) => new Date(stamp * 1000).toLocaleString(i18n.resolvedLanguage);
  const heartbeat = (stamp: number | null) => (stamp == null ? text("no_heartbeat") : date(stamp));
  const latest = data?.optimization.last;
  const optimizerHref = latest?.catalogId
    ? "/dns?" + new URLSearchParams({ catalogId: latest.catalogId, access: latest.access, provider: latest.provider, zone: latest.zone, optimizer: "history" })
    : "/dns/catalog";

  return (
    <section aria-labelledby="dns-overview-heading" aria-busy={loading}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <h3 className="m-0" id="dns-overview-heading">
          {text("heading")}
        </h3>
        <div className="flex flex-wrap items-center gap-3">
          {data && <Link to="/dns/catalog">{t("dashboard.dns_overview.domains", { count: data.domains })}</Link>}
          {data && !error && (
            <Button loading={loading} onClick={refresh}>
              {t("dns.refresh")}
            </Button>
          )}
        </div>
      </div>
      {error && <Alert type="error" showIcon title={text("load_error")} action={<Button onClick={refresh}>{t("dns.refresh")}</Button>} />}
      {loading && !data && <Skeleton active paragraph={{ rows: 3 }} />}
      {data && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 2xl:grid-cols-4">
          <SummaryCard
            title={text("failover")}
            to="/dns/automation"
            total={data.failover.total}
            entries={[
              [text("active"), data.failover.active],
              [text("primary"), data.failover.primary],
              [text("backup"), data.failover.backup],
              [text("scheduled"), data.scheduled],
              [
                text("scheduler"),
                data.failover.running == null ? (
                  text("no_heartbeat")
                ) : (
                  <Tag className="me-0" color={data.failover.running ? "success" : "warning"} title={heartbeat(data.failover.heartbeat)}>
                    {text(data.failover.running ? "running" : "stale")}
                  </Tag>
                ),
              ],
              [text("heartbeat"), heartbeat(data.failover.heartbeat)],
            ]}
          />
          <SummaryCard
            title={text("optimization")}
            to={optimizerHref}
            total={data.optimization.total}
            entries={[
              [text("active"), data.optimization.active],
              [text("succeeded"), data.optimization.succeeded],
              [text("failed"), data.optimization.failed],
              [text("heartbeat"), heartbeat(data.optimization.heartbeat)],
              [
                text("last_result"),
                latest ? (
                  <span>
                    {text(latest.status === "success" ? "succeeded" : "failed")} · {date(latest.at)}
                  </span>
                ) : (
                  text("no_result")
                ),
              ],
            ]}
          />
          <SummaryCard
            title={text("orders")}
            to="/dns-cert"
            total={data.orders.total}
            entries={[
              [text("issued"), data.orders.issued],
              [text("issue_failed"), data.orders.failed],
              [text("expiring"), data.orders.expiring],
              [text("expired"), data.orders.expired],
            ]}
          />
          <SummaryCard
            title={text("deployments")}
            to="/dns-cert/deployments"
            total={data.deployments.total}
            entries={[
              [text("pending"), data.deployments.pending, "/dns-cert/deployments?status=0"],
              [text("succeeded"), data.deployments.succeeded, "/dns-cert/deployments?status=1"],
              [text("failed"), data.deployments.failed, "/dns-cert/deployments?status=-1"],
            ]}
          />
        </div>
      )}
    </section>
  );
}
