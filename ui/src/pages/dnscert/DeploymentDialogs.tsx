import { useState } from "react";
import { Alert, Checkbox, Form, Input, Modal, Space, Typography } from "antd";

import {
  type BatchAction,
  type Deployment,
  type DeploymentChange,
  type DeploymentOrder,
  type DeploymentTarget,
  type SingleAction,
  actionLabels,
  deploymentPath,
  deploymentStatus,
  useDeploymentError,
  useExactDeploymentOrder,
  useExactDeploymentTarget,
} from "./deployment";
import { DeploymentOrderChoice, DeploymentTargetChoice } from "./DeploymentChoices";
import { useLabel } from "./order";

type SendChange = (change: DeploymentChange) => Promise<void>;
type DialogProps = { busy: boolean; close: () => void; send: SendChange };

export function DeploymentEditor({ task, orderId, busy, close, send }: DialogProps & { task?: Deployment; orderId: string }) {
  const label = useLabel();
  const describeError = useDeploymentError();
  const exactOrder = useExactDeploymentOrder(task?.orderId ?? orderId);
  const exactTarget = useExactDeploymentTarget(task);
  const [chosenOrder, setOrder] = useState<DeploymentOrder | null>();
  const [chosenTarget, setTarget] = useState<DeploymentTarget | null>();
  const [remark, setRemark] = useState(task?.remark ?? "");
  const [automatic, setAutomatic] = useState(task?.automatic ?? false);
  const [followRenewal, setFollowRenewal] = useState(task?.followRenewal ?? false);
  const [review, setReview] = useState(false);
  const order = chosenOrder === undefined ? exactOrder.data?.items[0] : (chosenOrder ?? undefined);
  const target = chosenTarget === undefined ? exactTarget.data?.items[0] : (chosenTarget ?? undefined);
  const rebind = !!task && !!order && order.id !== task.orderId;
  const retarget = !!task && !!target && (task.accessId !== target.accessId || task.workflowId !== target.workflowId || task.nodeId !== target.nodeId);
  const remarkTooLong = new TextEncoder().encode(remark).length > 256;

  function submit() {
    if (!order || !target) return;
    void send({
      path: task ? deploymentPath(task.id) : "",
      method: task ? "PATCH" : "POST",
      body: {
        orderId: order.id,
        accessId: target.accessId,
        workflowId: target.workflowId,
        nodeId: target.nodeId,
        remark: remark.trim(),
        confirmed: true,
        automatic,
        followRenewal,
        ...(task ? { version: task.version, ...(rebind ? { rebind: true } : {}) } : {}),
      },
    });
  }

  return (
    <Modal
      open
      title={task ? label("Edit deployment task", "编辑部署任务") : label("New deployment task", "新建部署任务")}
      okText={review ? label("Confirm and save", "确认保存") : label("Review task", "核对任务")}
      okButtonProps={{ disabled: !order || !target || remarkTooLong }}
      confirmLoading={busy}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: false }}
      cancelText={review ? label("Back to editing", "返回编辑") : label("Cancel", "取消")}
      cancelButtonProps={{ disabled: busy }}
      onCancel={() => (review ? setReview(false) : close())}
      onOk={() => (review ? submit() : setReview(true))}
    >
      <Form layout="vertical" disabled={busy || review}>
        <Form.Item label={label("Certificate order", "证书订单")} htmlFor="deployment-order" required>
          <DeploymentOrderChoice
            id="deployment-order"
            ariaLabel={label("Certificate order", "证书订单")}
            disabled={busy || review}
            value={order}
            onChange={(value) => setOrder(value ?? null)}
          />
          {exactOrder.error && chosenOrder === undefined && <Alert type="error" showIcon title={describeError(exactOrder.error)} />}
        </Form.Item>
        <Form.Item label={label("Published deployment target", "已发布部署目标")} htmlFor="deployment-target" required>
          <DeploymentTargetChoice
            id="deployment-target"
            ariaLabel={label("Published deployment target", "已发布部署目标")}
            disabled={busy || review}
            value={target}
            onChange={(value) => setTarget(value ?? null)}
          />
          {exactTarget.error && chosenTarget === undefined && <Alert type="error" showIcon title={describeError(exactTarget.error)} />}
          {task && exactTarget.data?.items.length === 0 && chosenTarget === undefined && (
            <Alert
              type="warning"
              showIcon
              title={label("The previous target is unavailable. Select a published target.", "原部署目标不可用，请选择已发布目标。")}
            />
          )}
        </Form.Item>
        <Form.Item
          label={label("Remark", "备注")}
          htmlFor="deployment-remark"
          validateStatus={remarkTooLong ? "error" : undefined}
          help={remarkTooLong ? label("Use at most 256 bytes.", "备注最多 256 字节。") : undefined}
        >
          <Input id="deployment-remark" maxLength={256} value={remark} onChange={(event) => setRemark(event.target.value)} />
        </Form.Item>
        <Space orientation="vertical">
          <Checkbox
            checked={automatic}
            onChange={(event) => {
              setAutomatic(event.target.checked);
              if (!event.target.checked) setFollowRenewal(false);
            }}
          >
            {label("Deploy automatically after the certificate is ready", "证书就绪后自动部署")}
          </Checkbox>
          <Checkbox disabled={!automatic || busy || review} checked={followRenewal} onChange={(event) => setFollowRenewal(event.target.checked)}>
            {label("Also deploy successfully renewed certificates", "同时部署续期成功的证书")}
          </Checkbox>
          {followRenewal && (
            <Typography.Text type="secondary">
              {label("Select the current order of an enabled renewal schedule.", "请选择已启用续期计划的当前订单。")}
            </Typography.Text>
          )}
        </Space>
      </Form>
      {review && (
        <Space orientation="vertical" className="mt-4 w-full">
          {!task && (
            <Alert type="info" showIcon title={label("New tasks start paused. Enable the task when it is ready.", "新任务初始为暂停。准备就绪后可启用。")} />
          )}
          {rebind && (
            <Alert
              type="warning"
              showIcon
              title={label("Confirm the order change", "确认更换关联订单")}
              description={label(
                "This replaces the linked order and resets the task state. Previous attempts remain in the log.",
                "将更换关联订单并重置任务状态，历史尝试仍可在日志中查看。"
              )}
            />
          )}
          {retarget && (
            <Alert
              type="warning"
              showIcon
              title={label("Changing the published target resets the current deployment result.", "更换已发布目标将重置当前部署结果。")}
            />
          )}
          {automatic && (
            <Alert
              type="warning"
              showIcon
              title={label(
                "You authorize scheduled delivery of the certificate and private key to this published target while the task is enabled.",
                "您授权系统在任务启用期间，将证书和私钥定时部署至此已发布目标。"
              )}
            />
          )}
        </Space>
      )}
    </Modal>
  );
}

export function DeploymentActionDialog({
  action,
  tasks,
  batch,
  busy,
  close,
  send,
}: DialogProps & { tasks: Deployment[]; action: SingleAction | BatchAction; batch: boolean }) {
  const label = useLabel();
  const [order, setOrder] = useState<DeploymentOrder>();
  const [reconciled, setReconciled] = useState(false);
  const task = tasks[0];
  const isReset = action === "reset";
  const needsReconciliation = isReset && tasks.some((item) => deploymentStatus(item) === "reconcile");
  const runAgain = action === "process" && task.status === 1;
  const actions = {
    enable: label(
      "Enabled tasks can be run manually. Tasks with current automation approval can also run on schedule.",
      "启用后可以手动部署。已有有效自动部署授权的任务也可由计划运行。"
    ),
    pause: label(
      "Pause manual and scheduled deployment for the selected tasks. Automation approval remains on record.",
      "暂停所选任务的手动和计划部署，已有的自动部署授权仍会保留。"
    ),
    reset: label(
      "Reset the current deployment state and turn off automatic deployment. Previous attempts remain in the log.",
      "重置当前部署状态并关闭自动部署，历史尝试仍可在日志中查看。"
    ),
    delete: label("Remove the selected deployment tasks.", "删除所选部署任务。"),
    rebind: label(
      "Replace the linked order for every selected task, reset their deployment state, and turn off automatic deployment.",
      "为所选任务更换关联订单、重置部署状态并关闭自动部署。"
    ),
    process: runAgain
      ? label("Deploy the certificate and private key to this target again after a successful run.", "此前部署已成功，将再次向此目标部署证书和私钥。")
      : label("Deploy the certificate and private key to this published target.", "将证书和私钥部署至此已发布目标。"),
  };
  const title = runAgain ? label("Deploy again", "再次部署") : label(...actionLabels[action]);

  function submit() {
    if ((needsReconciliation && !reconciled) || (action === "rebind" && !order)) return;
    const body = { confirmed: true, ...(needsReconciliation && reconciled ? { reconciled: true } : {}) };
    if (batch) {
      void send({
        path: "/batch",
        method: "POST",
        body: { ...body, action, tasks: tasks.map(({ id, version }) => ({ id, version })), ...(order ? { orderId: order.id } : {}) },
      });
      return;
    }
    const path = deploymentPath(task.id);
    const version = task.version;
    if (action === "delete") void send({ path, method: "DELETE", body: { ...body, version } });
    else if (action === "enable" || action === "pause")
      void send({ path: path + "/active", method: "POST", body: { ...body, version, active: action === "enable" } });
    else void send({ path: path + "/" + action, method: "POST", body: { ...body, version, ...(runAgain ? { runAgain: true } : {}) } });
  }

  return (
    <Modal
      open
      title={title}
      okText={title}
      okButtonProps={{ danger: action === "delete", disabled: (needsReconciliation && !reconciled) || (action === "rebind" && !order) }}
      confirmLoading={busy}
      closable={!busy}
      keyboard={!busy}
      mask={{ closable: false }}
      cancelButtonProps={{ disabled: busy }}
      onCancel={close}
      onOk={submit}
    >
      <Space orientation="vertical" className="w-full">
        <Typography.Text>{actions[action]}</Typography.Text>
        <ul className="max-h-48 list-disc overflow-y-auto pl-5">
          {tasks.map((item) => (
            <li key={item.id} className="break-all">
              <strong>{item.domain || item.orderId}</strong> · {item.workflowName || item.workflowId} · {item.nodeId} · {item.accessName || item.accessId}
              {item.remark && " · " + item.remark}
            </li>
          ))}
        </ul>
        {action === "rebind" && (
          <Form layout="vertical">
            <Form.Item label={label("New certificate order", "新的证书订单")} htmlFor="deployment-rebind-order" required>
              <DeploymentOrderChoice
                id="deployment-rebind-order"
                ariaLabel={label("New certificate order", "新的证书订单")}
                disabled={busy}
                value={order}
                onChange={setOrder}
              />
            </Form.Item>
          </Form>
        )}
        {needsReconciliation && (
          <Checkbox disabled={busy} checked={reconciled} onChange={(event) => setReconciled(event.target.checked)}>
            {label("I checked the destination and reconciled any incomplete transfer.", "我已核对部署目标并处理可能未完成的传输。")}
          </Checkbox>
        )}
      </Space>
    </Modal>
  );
}
