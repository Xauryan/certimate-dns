import { useTranslation } from "react-i18next";
import { useRequest } from "ahooks";

import { getPocketBase } from "@/repository/_pocketbase";

export interface Account {
  id: string;
  provider: string;
  name: string;
}

export interface Challenge {
  name: string;
  type: string;
  value: string;
}

export interface Order {
  id: string;
  provider: string;
  accessId: string;
  domain: string;
  algorithm: string;
  state: string;
  remoteId?: string;
  certificateId?: string;
  challenges?: Challenge[];
  allowedActions?: Action[];
  version: number;
}

export interface Page<T> {
  items: T[];
  total: number;
}

export interface Zone {
  id: string;
  name: string;
  accountId: string;
}

export function request<T>(path: string, body?: object): Promise<T> {
  return getPocketBase().send<T>("/api/dnscert" + path, { method: body ? "POST" : "GET", body, requestKey: null });
}

export function useResource<T>(path: string) {
  return useRequest(() => request<T>(path), { refreshDeps: [path] });
}

export function useLabel() {
  const { i18n } = useTranslation();
  const chinese = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh");
  return (en: string, zh: string) => (chinese ? zh : en);
}

type Labels = readonly [en: string, zh: string];

export const providers = {
  aliyun: ["Alibaba Cloud", "阿里云"],
  tencentcloud: ["Tencent Cloud", "腾讯云"],
  ucloud: ["UCloud", "优刻得"],
} satisfies Record<string, Labels>;

export const actions = {
  create: ["Reserve order", "创建云端订单"],
  submit: ["Submit application", "提交签发申请"],
  refresh: ["Check status", "查询云端状态"],
  verify: ["Start verification", "启动域名验证"],
  present: ["Add validation records", "添加验证记录"],
  cleanup: ["Remove validation records", "清理验证记录"],
  download: ["Import certificate", "导入证书库"],
  cancel: ["Cancel order", "取消订单"],
  revoke: ["Revoke certificate", "吊销证书"],
  recover: ["Link existing order", "关联已有订单"],
  reset: ["Start a new draft", "重新申请"],
  delete: ["Delete draft", "删除草稿"],
  edit: ["Edit draft", "编辑草稿"],
} satisfies Record<string, Labels>;

export type Action = keyof typeof actions;

export const states: Record<string, Labels> = {
  draft: ["Draft", "草稿"],
  creating: ["Reserving", "正在创建"],
  reserved: ["Reserved", "已创建云端订单"],
  submitting: ["Submitting", "正在提交"],
  pending: ["Awaiting verification", "等待验证"],
  issued: ["Issued", "已签发"],
  failed: ["Failed", "失败"],
  cancelled: ["Cancelled", "已取消"],
  revoking: ["Revocation pending", "等待吊销"],
  revoked: ["Revoked", "已吊销"],
  imported: ["Imported", "已导入"],
  expired: ["Expired", "已过期"],
  cancelling: ["Cancellation pending", "等待取消"],
  uncertain: ["Needs reconciliation", "待核对云端状态"],
};

export const confirmations = {
  create: [
    "This requests a certificate order from the selected cloud account. The provider may use an instance or quota.",
    "将使用所选云账号创建证书订单，服务商可能扣减证书实例或额度。",
  ],
  submit: ["Send this domain and its application details to the issuer.", "将此域名及申请资料提交给签发机构。"],
  verify: ["Ask the issuer to verify the published DNS records.", "请求签发机构检查已发布的 DNS 验证记录。"],
  present: ["Select the DNS zone where the validation records should be created.", "选择用于添加域名验证记录的 DNS 区域。"],
  cleanup: ["Remove the DNS records this order added for validation.", "删除此订单为域名验证添加的 DNS 记录。"],
  download: ["Retrieve the issued certificate and private key into the Certimate certificate inventory.", "将已签发的证书和私钥存入 Certimate 证书库。"],
  cancel: ["Cancel the selected order.", "取消所选订单。"],
  delete: ["Delete this local draft.", "删除此本地订单草稿。"],
  reset: ["Create a new draft from this application. The previous order remains in history.", "根据已有申请资料新建草稿，原订单可继续在历史记录中查看。"],
  revoke: ["Revoke this certificate with the issuer. This can interrupt services using it.", "向签发机构申请吊销此证书，使用该证书的服务可能中断。"],
  recover: ["Enter the order or instance ID shown in the provider console for this domain.", "请填写服务商控制台中此域名对应的订单或实例 ID。"],
} satisfies Record<Exclude<Action, "refresh" | "edit">, Labels>;
