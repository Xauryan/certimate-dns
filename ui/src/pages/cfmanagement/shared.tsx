import { useEffect, useRef, useState, type ReactNode } from "react";
import { useTranslation } from "react-i18next";
import { Alert, App, Button, Form, Input, Modal, Select, Space } from "antd";
import { dnsRequest, type Page } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

export function useLabel() {
  const { i18n } = useTranslation();
  return (en: string, zh: string) => (i18n.language.startsWith("zh") ? zh : en);
}

export function useResource<T>(url: string) {
  const [revision, setRevision] = useState(0);
  const [loaded, setLoaded] = useState<{ url: string; revision: number; data?: T; error?: string }>();
  useEffect(() => {
    let active = true;
    dnsRequest<T>(url).then(
      (data) => {
        if (active) setLoaded({ url, revision, data });
      },
      (err) => {
        if (active) setLoaded({ url, revision, error: unwrapErrMsg(err) });
      }
    );
    return () => {
      active = false;
    };
  }, [url, revision]);
  const result = loaded?.url === url && loaded.revision === revision ? loaded : undefined;
  return { data: result?.data, error: result?.error, loading: !result, reload: () => setRevision((v) => v + 1) };
}

export function usePage<T>(url: string) {
  const [page, setPage] = useState(1);
  const resource = useResource<Page<T>>(url + "?page=" + page);
  return { ...resource, rows: resource.data?.result ?? [], page, setPage, total: resource.data?.result_info?.total_count };
}

export function PageControls({
  page,
  setPage,
  total,
  count,
  loading,
}: {
  page: number;
  setPage: (n: number) => void;
  total?: number;
  count: number;
  loading: boolean;
}) {
  const l = useLabel();
  return (
    <Space>
      <Button disabled={loading || page === 1} onClick={() => setPage(page - 1)}>
        {l("Previous", "上一页")}
      </Button>
      {page}
      <Button disabled={loading || (total ? page * 20 >= total : count < 20)} onClick={() => setPage(page + 1)}>
        {l("Next", "下一页")}
      </Button>
    </Space>
  );
}

export function ScopeSelect({ url, label, value, choose }: { url: string; label: string; value?: string; choose: (id: string) => void }) {
  const resource = usePage<{ id: string; name: string }>(url);
  return (
    <>
      <Space wrap>
        <Select
          aria-label={label}
          placeholder={label}
          loading={resource.loading}
          value={value}
          style={{ minWidth: 230 }}
          options={resource.rows.map((i) => ({ value: i.id, label: i.name }))}
          onChange={choose}
        />
        <PageControls {...resource} count={resource.rows.length} />
      </Space>
      {resource.error && <LoadError text={resource.error} retry={resource.reload} />}
    </>
  );
}
export function LoadError({ text, retry }: { text: string; retry: () => void }) {
  const l = useLabel();
  return <Alert type="error" showIcon title={text} action={<Button onClick={retry}>{l("Retry", "重试")}</Button>} />;
}

export interface Field {
  key: string;
  label: string;
  options?: string[];
  required?: boolean;
  multiline?: boolean;
  initial?: string;
}

export type Values = Record<string, string>;

export function Editor({
  title,
  fields,
  save,
  close,
  children,
}: {
  title: string;
  fields: Field[];
  save: (values: Values) => Promise<void>;
  close: () => void;
  children?: ReactNode;
}) {
  const [form] = Form.useForm<Values>();
  const [busy, setBusy] = useState(false);
  const running = useRef(false);
  const [error, setError] = useState("");
  const l = useLabel();
  return (
    <Modal
      open
      title={title}
      okText={l("Save", "保存")}
      confirmLoading={busy}
      cancelButtonProps={{ disabled: busy }}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: !busy }}
      onCancel={() => {
        if (!busy) close();
      }}
      onOk={() => form.submit()}
    >
      {error && <Alert type="error" showIcon title={error} />}
      <Form
        layout="vertical"
        form={form}
        disabled={busy}
        initialValues={Object.fromEntries(fields.map((f) => [f.key, f.initial]))}
        onFinish={async (values) => {
          if (running.current) return;
          running.current = true;
          setBusy(true);
          setError("");
          try {
            await save(values);
            close();
          } catch (e) {
            setError(unwrapErrMsg(e));
          } finally {
            running.current = false;
            setBusy(false);
          }
        }}
      >
        {children}
        {fields.map((f) => (
          <Form.Item key={f.key} label={f.label} name={f.key} rules={[{ required: f.required, whitespace: true }]}>
            {f.options ? <Select options={f.options.map((v) => ({ label: v, value: v }))} /> : f.multiline ? <Input.TextArea rows={4} /> : <Input />}
          </Form.Item>
        ))}
      </Form>
    </Modal>
  );
}

export function useConfirm() {
  const { modal, message } = App.useApp();
  const l = useLabel();
  return (title: string, target: string, action: () => Promise<unknown>, refresh: () => void) => {
    modal.confirm({
      title,
      content: target,
      okButtonProps: { danger: true },
      onOk: async () => {
        try {
          await action();
          message.success(l("Saved", "已保存"));
        } catch (e) {
          message.error(unwrapErrMsg(e));
        } finally {
          refresh();
        }
      },
    });
  };
}
