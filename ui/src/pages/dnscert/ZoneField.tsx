import { useState } from "react";
import { Alert, Pagination, Select } from "antd";
import { unwrapErrMsg } from "@/utils/error";
import { type Page, type Zone, useLabel, useResource } from "./order";

type Selection = { orderId: string; domain?: never } | { domain: string; orderId?: never };
type Props = Selection & { id?: string; value?: string; disabled?: boolean; onChange?: (value: string | undefined) => void };
export default function ZoneField({ id, orderId, domain, disabled, value, onChange }: Props) {
  const label = useLabel();
  const [page, setPage] = useState(1);
  const zones = useResource<Page<Zone>>("/zones?" + new URLSearchParams({ ...(orderId ? { orderId } : { domain: domain ?? "" }), page: String(page) }));
  return (
    <div className="flex flex-col gap-2">
      <Select
        id={id}
        allowClear={!orderId}
        value={value}
        onChange={onChange}
        loading={zones.loading}
        disabled={disabled || zones.loading || !!zones.error}
        placeholder={label("Select a DNS zone", "选择 DNS 区域")}
        options={zones.data?.items.map((z) => ({ value: z.id, label: z.name + " · " + z.accountId }))}
      />
      {zones.error && <Alert type="error" showIcon title={unwrapErrMsg(zones.error)} />}
      {(zones.data?.total ?? 0) > 20 && (
        <Pagination
          size="small"
          current={page}
          pageSize={20}
          showSizeChanger={false}
          total={zones.data?.total}
          onChange={(p) => {
            onChange?.(undefined);
            setPage(p);
          }}
        />
      )}
    </div>
  );
}
