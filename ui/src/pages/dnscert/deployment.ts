import { useRequest } from "ahooks";
import { ClientResponseError } from "pocketbase";

import { getPocketBase } from "@/repository/_pocketbase";
import { useLabel } from "./order";

export interface Deployment {
  id: string;
  orderId: string;
  domain: string;
  orderState: string;
  accessId: string;
  accessName: string;
  provider: string;
  workflowId: string;
  workflowName: string;
  nodeId: string;
  remark: string;
  active: boolean;
  status: number;
  version: number;
  processId: string;
  started: number;
  finished: number;
  created: number;
  automatic: boolean;
  followRenewal: boolean;
  policyCurrent: boolean;
  result?: string;
}

export interface DeploymentOrder {
  id: string;
  domain: string;
  state: string;
}

export interface DeploymentTarget {
  accessId: string;
  accessName: string;
  provider: string;
  workflowId: string;
  workflowName: string;
  nodeId: string;
  nodeName: string;
}

export interface DeploymentAttempt {
  id: string;
  certificateId?: string;
  orderId: string;
  domain: string;
  accessId: string;
  workflowId: string;
  nodeId: string;
  provider: string;
  trigger: string;
  started: number;
  finished: number;
  outcome: string;
}

export type SingleAction = "enable" | "pause" | "reset" | "delete" | "process";
export type BatchAction = Exclude<SingleAction, "process"> | "rebind";
export type DeploymentChange = {
  path: string;
  method: "POST" | "PATCH" | "DELETE";
  body: object;
};

export const pageSize = 20;
export const deploymentPath = (id: string) => "/" + encodeURIComponent(id);

export function deploymentRequest<T>(path: string, method = "GET", body?: object) {
  return getPocketBase().send<T>("/api/dnscert/deployments" + path, { method, body, requestKey: null });
}

export function useDeploymentResource<T>(path: string, ready = true) {
  const resource = useRequest(async () => ({ path, response: await deploymentRequest<T>(path) }), { refreshDeps: [path], ready });
  return { ...resource, data: ready && resource.data?.path === path ? resource.data.response : undefined };
}

export function useExactDeploymentOrder(orderId: string) {
  return useDeploymentResource<{ items: DeploymentOrder[] }>("/orders?" + new URLSearchParams({ id: orderId }), !!orderId);
}

export function useExactDeploymentTarget(task?: Deployment) {
  const params = new URLSearchParams({ accessId: task?.accessId ?? "", workflowId: task?.workflowId ?? "", nodeId: task?.nodeId ?? "" });
  return useDeploymentResource<{ items: DeploymentTarget[] }>("/targets?" + params, !!task);
}

export function deploymentStatus(task: Deployment) {
  if (task.started && !task.finished) return Date.now() / 1000 - task.started >= 3600 ? "reconcile" : "running";
  if (task.status === 1) return "succeeded";
  return task.status === -1 ? "reconcile" : "pending";
}

export const statusLabels = {
  pending: ["Pending", "待部署"],
  running: ["In progress", "部署中"],
  succeeded: ["Succeeded", "已部署"],
  reconcile: ["Needs reconciliation", "待核对目标"],
} satisfies Record<string, [string, string]>;

export const actionLabels = {
  process: ["Deploy now", "立即部署"],
  enable: ["Enable", "启用"],
  pause: ["Pause", "暂停"],
  reset: ["Reset", "重置"],
  delete: ["Delete", "删除"],
  rebind: ["Rebind order", "更换关联订单"],
} satisfies Record<string, [string, string]>;

export function formatDeploymentTime(seconds: number) {
  return seconds ? new Date(seconds * 1000).toLocaleString() : "—";
}

export function useDeploymentError() {
  const label = useLabel();
  return (err: unknown) => {
    const code = err instanceof ClientResponseError ? err.status : 0;
    if (code === 401 || code === 403) return label("An active administrator session is required.", "需要有效的管理员会话。");
    if (code === 404) return label("The deployment task, order, or published target is unavailable.", "部署任务、关联订单或已发布目标不可用。");
    if (code === 400) return label("Check the order, published target, and deployment settings.", "请核对订单、已发布目标和部署设置。");
    if (code === 409) {
      return label(
        "Review the latest task state and destination before trying again. Following renewals requires the current order of an enabled renewal schedule.",
        "重试前请核对最新任务状态和部署目标。跟随续期需要选择已启用续期计划的当前订单。"
      );
    }
    return label("The deployment request could not be confirmed. Refresh and check the latest state.", "无法确认部署请求的结果，请刷新并核对最新状态。");
  };
}
