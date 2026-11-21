import { getPocketBase } from "@/repository/_pocketbase";

export type NetworkInterface = {
  name: string;
  mac: string;
  ipv4: string[];
  ipv6: string[];
};

export type BindingTarget = {
  provider: string;
  accessId: string;
  zoneId: string;
  recordId: string;
  interfaceName: string;
};

export type Binding = BindingTarget & {
  id: string;
  recordName: string;
  recordType: string;
  lastAddress: string;
  syncStatus: string;
  lastError: string;
  updatedAt: string | null;
};

export type Node = {
  id: string;
  name: string;
  hostname: string;
  lastSeen: string | null;
  enabled: boolean;
  online: boolean;
  interfaces: NetworkInterface[];
  bindings: Binding[];
};

export type IssuedToken = { id: string; token: string };

export function ddnsRequest<T>(path: string, method = "GET", body?: object) {
  return getPocketBase().send<T>("/api/ddns/nodes" + path, { method, body, requestKey: null });
}

export function nodePath(id: string) {
  return "/" + encodeURIComponent(id);
}
