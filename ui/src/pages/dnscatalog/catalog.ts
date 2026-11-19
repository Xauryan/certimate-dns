import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { dnsRequest } from "@/api/dns";
import { unwrapErrMsg } from "@/utils/error";

export const base = "/api/dns-catalog";
export type Category = { id: string; name: string; remark: string; sort: number; domain_count: number };
export type Account = { notes: string; domainCount: number; id: string; name: string; provider: string; enabled: boolean };
export type Metadata = {
  hidden: boolean;
  autoRefresh: boolean;
  tags: string[];
  groupName: string;
  notes: string;
  expiresOn: string;
  reminderDays: number;
  reminderEnabled: boolean;
  notificationId: string;
};
export type Zone = Metadata & {
  registeredOn: string;
  registrationStatus: string;
  registrationChecked: string;
  categoryId: string;
  id: string;
  name: string;
  accessId: string;
  accountName: string;
  provider: string;
  zoneId: string;
  present: boolean;
  enabled: boolean;
  status: string;
};
export type ResourceLink = { id: string; name: string };
export type Details = Zone & {
  certificates: { id: string; subjectName: string; subjectAltNames: string; expires: string }[];
  workflows: ResourceLink[];
  tasks: ResourceLink[];
};

export function useCatalog<T>(path: string | undefined, revision: number, absolute = false) {
  const [result, setResult] = useState<{ path: string; revision: number; data?: T; error?: string }>();
  useEffect(() => {
    if (!path) return;
    let active = true;
    dnsRequest<T>(absolute ? path : base + path).then(
      (data) => {
        if (active) setResult({ path, revision, data });
      },
      (e) => {
        if (active) setResult({ path, revision, error: unwrapErrMsg(e) });
      }
    );
    return () => {
      active = false;
    };
  }, [path, revision, absolute]);
  return result && result.path === path && result.revision === revision ? result : undefined;
}

export function useLabels() {
  const { i18n } = useTranslation();
  return i18n.language.toLowerCase().startsWith("zh")
    ? {
        title: "域名目录",
        createRemote: "在服务商创建域名",
        importZones: "导入所选域名",
        batch: "应用到所选域名",
        category: "分类",
        removeLocal: "从目录移除",
        removeExplanation: "这些域名将从本地目录移除，关联的成员授权也会移除。",
        addCategory: "新增分类",
        removeCategory: "删除分类",
        manage: "管理",
        edit: "编辑",
        sort: "排序",
        registered: "注册日期（UTC）",
        refreshDates: "查询注册日期",
        autoRefresh: "定期刷新注册日期和到期日",
        lastCheck: "最近查询",
        failed: "查询失败，保留上次记录",
        ok: "已更新",
        hidden: "从成员域名列表中隐藏",
        domains: "域名",
        accounts: "DNS 账号",
        allAccounts: "全部账号",
        access: "管理授权",
        name: "名称",
        account: "账号",
        provider: "服务商",
        enabled: "启用 DNS 管理",
        sync: "同步域名",
        synced: "已同步域名数",
        active: "已同步",
        missing: "服务商已移除",
        disabled: "账号已禁用",
        status: "状态",
        group: "分组",
        tags: "标签",
        notes: "备注",
        search: "搜索域名或备注",
        tagFilter: "筛选标签",
        groupFilter: "筛选分组",
        expiry: "注册到期日（UTC）",
        due: "到期提醒",
        reminder: "启用到期提醒",
        days: "提前天数",
        channel: "通知渠道",
        inbox: "仅在到期提醒列表中显示",
        save: "保存",
        saved: "已保存",
        records: "解析记录",
        certs: "证书",
        workflows: "工作流",
        tasks: "自动化任务",
        metadata: "域名资料",
        refresh: "刷新",
        empty: "暂无",
        back: "返回目录",
        advanced: "服务商功能",
      }
    : {
        title: "Domain catalog",
        createRemote: "Create at provider",
        importZones: "Import selected zones",
        batch: "Apply to selection",
        category: "Category",
        removeLocal: "Remove from catalog",
        removeExplanation: "Remove the selected local catalog entries and their member grants?",
        addCategory: "Add category",
        removeCategory: "Delete category",
        manage: "Manage",
        edit: "Edit",
        sort: "Sort order",
        registered: "Registered (UTC)",
        refreshDates: "Look up registration dates",
        autoRefresh: "Refresh registration dates automatically",
        lastCheck: "Last lookup",
        failed: "Lookup failed; previous dates retained",
        ok: "Updated",
        hidden: "Hide from member zone list",
        domains: "Domains",
        accounts: "DNS accounts",
        allAccounts: "All accounts",
        access: "Manage credentials",
        name: "Name",
        account: "Account",
        provider: "Provider",
        enabled: "DNS management enabled",
        sync: "Sync zones",
        synced: "Zones synced",
        active: "Synced",
        missing: "Removed at provider",
        disabled: "Account disabled",
        status: "Status",
        group: "Group",
        tags: "Tags",
        notes: "Notes",
        search: "Search domains or notes",
        tagFilter: "Filter by tag",
        groupFilter: "Filter by group",
        expiry: "Registration expiry (UTC)",
        due: "Expiry reminders",
        reminder: "Enable expiry reminder",
        days: "Days before expiry",
        channel: "Notification channel",
        inbox: "Show only in expiry reminders",
        save: "Save",
        saved: "Saved",
        records: "DNS records",
        certs: "Certificates",
        workflows: "Workflows",
        tasks: "Automation tasks",
        metadata: "Domain details",
        refresh: "Refresh",
        empty: "None",
        back: "Back to catalog",
        advanced: "Provider features",
      };
}
