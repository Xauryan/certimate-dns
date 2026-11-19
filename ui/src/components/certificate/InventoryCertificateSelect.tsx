import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useDebounce, useRequest } from "ahooks";
import { Alert, Pagination, Select } from "antd";
import dayjs from "dayjs";

import { listDeployable } from "@/repository/certificate";
import { unwrapErrMsg } from "@/utils/error";

interface InventoryCertificateSelectProps {
  id?: string;
  value?: string;
  onChange?: (value: string) => void;
}

const InventoryCertificateSelect = (props: InventoryCertificateSelectProps) => {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const keyword = useDebounce(query.trim(), { wait: 200 });
  const { data, loading, error } = useRequest(() => listDeployable(keyword, page), { refreshDeps: [keyword, page] });

  return (
    <div className="flex flex-col gap-2">
      <Select
        {...props}
        showSearch={{
          filterOption: false,
          onSearch: (value) => {
            setPage(1);
            setQuery(value);
          },
        }}
        loading={loading}
        placeholder={t("workflow_node.upload.form.inventory.placeholder")}
        options={data?.items.map((r) => ({
          value: r.id,
          label: [r.subjectAltNames, dayjs(r.validityNotAfter).format("YYYY-MM-DD"), r.id].join(" · "),
        }))}
      />
      {error && <Alert type="error" showIcon title={unwrapErrMsg(error)} />}
      {!!data && data.totalPages > 1 && (
        <Pagination size="small" pageSize={20} current={page} total={data.totalItems} onChange={setPage} showSizeChanger={false} />
      )}
    </div>
  );
};

export default InventoryCertificateSelect;
