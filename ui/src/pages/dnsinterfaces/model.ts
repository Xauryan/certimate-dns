import { useTranslation } from "react-i18next";

import { dnsRequest } from "@/api/dns";
import { getPocketBase } from "@/repository/_pocketbase";

export type Zone = { id: string; name: string; provider: string; accessId: string; canWrite: boolean };
export type KeyScope = { interfaces: string[]; actions: string[]; zones: string[]; accounts?: string[]; global?: boolean };
export type KeyRow = { uid: string; label: string; scope: KeyScope };
export type Issued = { uid: string; apikey: string };
export type Label = (en: string, zh: string) => string;

export function useLabel(): Label {
  const { i18n } = useTranslation();
  const zh = (i18n.resolvedLanguage ?? i18n.language).startsWith("zh");
  return (en, cn) => (zh ? cn : en);
}

export function keyRequest<T>(path = "", method = "GET", body?: object) {
  return getPocketBase().send<T>("/api/dns-keys" + path, { method, body, requestKey: null });
}

export const pageSize = 10;

export const listZones = (page: number) => dnsRequest<{ items: Zone[]; total: number }>(`/api/dns-member/zones?page=${page}&perPage=${pageSize}`);
