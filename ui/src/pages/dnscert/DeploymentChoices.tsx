import { useState } from "react";
import { useDebounce } from "ahooks";
import { Alert, Select } from "antd";

import { type DeploymentOrder, type DeploymentTarget, useDeploymentError, useDeploymentResource } from "./deployment";
import { states, useLabel } from "./order";

interface ChoiceProps<T> {
  id?: string;
  ariaLabel: string;
  disabled?: boolean;
  value?: T;
  onChange?: (value: T | undefined) => void;
}

function PublishedChoice<T>({
  id,
  ariaLabel,
  disabled,
  value,
  onChange,
  endpoint,
  placeholder,
  identify,
  describe,
}: ChoiceProps<T> & { endpoint: string; placeholder: string; identify: (item: T) => string; describe: (item: T) => string }) {
  const label = useLabel();
  const describeError = useDeploymentError();
  const [search, setSearch] = useState("");
  const keyword = useDebounce(search, { wait: 300 });
  const resource = useDeploymentResource<{ items: T[] }>(endpoint + "?" + new URLSearchParams({ q: keyword }));
  const options = search === keyword && !resource.error ? (resource.data?.items ?? []) : [];
  return (
    <div className="flex flex-col gap-2">
      <Select
        id={id}
        aria-label={ariaLabel}
        className="w-full"
        allowClear
        disabled={disabled}
        loading={resource.loading || search !== keyword}
        labelInValue
        showSearch={{ filterOption: false, onSearch: setSearch }}
        value={value ? { value: identify(value), label: describe(value) } : undefined}
        onChange={(option) => {
          onChange?.(options.find((item) => identify(item) === option?.value));
          setSearch("");
        }}
        options={options.map((item) => ({ value: identify(item), label: describe(item) }))}
        placeholder={placeholder}
        notFoundContent={resource.loading || search !== keyword ? label("Searching…", "搜索中…") : label("No matches", "没有匹配项")}
      />
      {resource.error && <Alert type="error" showIcon title={describeError(resource.error)} />}
    </div>
  );
}

export function DeploymentOrderChoice(props: ChoiceProps<DeploymentOrder>) {
  const label = useLabel();
  return (
    <PublishedChoice
      {...props}
      endpoint="/orders"
      placeholder={label("Search orders by domain or ID", "按域名或订单 ID 搜索")}
      identify={(order) => order.id}
      describe={(order) =>
        [order.domain, order.id, Object.hasOwn(states, order.state) ? label(...states[order.state]) : order.state].filter(Boolean).join(" · ")
      }
    />
  );
}

export function DeploymentTargetChoice(props: ChoiceProps<DeploymentTarget>) {
  const label = useLabel();
  return (
    <PublishedChoice
      {...props}
      endpoint="/targets"
      placeholder={label("Search published workflows, nodes, or accounts", "搜索已发布工作流、节点或部署账号")}
      identify={(target) => JSON.stringify([target.accessId, target.workflowId, target.nodeId])}
      describe={(target) =>
        [target.workflowName || target.workflowId, target.nodeName || target.nodeId, target.accessName || target.accessId, target.provider].join(" · ")
      }
    />
  );
}
