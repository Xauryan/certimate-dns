export interface Target {
  accountId: string;
  zoneId: string;
  recordId: string;
  name: string;
  type: string;
}

export interface Definition {
  name: string;
  kind: "schedule" | "failover";
  target: Target;
  action: string;
  value?: string;
  primary?: string;
  backup?: string;
  backupProxied?: boolean;
  schedule: { proxied?: boolean; cycle: string; at: string; day?: number; timezone?: string };
  monitor: {
    protocol: string;
    port: number;
    origin?: string;
    interval: number;
    timeout: number;
    failureThreshold: number;
    recoveryThreshold: number;
    cooldown: number;
    healthyLimit?: number;
  };
  notifyAccessId?: string;
}

export interface Task {
  id: string;
  definition: Definition;
  state: string;
  position: string;
  failures: number;
  recoveries: number;
  nextAt: number;
  lastAt: number;
  switchAt: number;
  version: number;
}
export interface Run {
  id: string;
  actor: string;
  action: string;
  outcome: string;
  started: number;
  finished: number;
  before?: string;
  after?: string;
  notification?: string;
}
export const base = "/api/dns-automation";
export const time = (value: number) => (value ? new Date(value * 1000).toLocaleString() : "—");
export type Label = (cn: string, en: string) => string;
