import { useTranslation } from "react-i18next";
import { Alert, Button, Descriptions, Space, Typography } from "antd";

import { type Binding } from "./model";

type Props = {
  rename: NonNullable<Binding["pendingRename"]>;
  canContinue: boolean;
  busy: boolean;
  error: string;
  onCheck: () => void;
  onCancel: () => void;
  onConfirmRecord: (id: string) => void;
};

export default function BindingRenameReview({ rename, canContinue, busy, error, onCheck, onCancel, onConfirmRecord }: Props) {
  const { t } = useTranslation();
  const candidate = rename.candidateRecordId;
  return (
    <>
      <Typography.Paragraph type="secondary">{t(rename.submitted ? "ddns.renameReviewHelp" : "ddns.renamePrepareHelp")}</Typography.Paragraph>
      <Descriptions
        className="mb-4"
        size="small"
        column={1}
        items={[
          { key: "name", label: t("ddns.requestedRecord"), children: rename.recordName },
          { key: "interface", label: t("ddns.requestedInterface"), children: rename.interfaceName },
          ...(candidate ? [{ key: "candidate", label: t("ddns.newRecordId"), children: candidate }] : []),
        ]}
      />
      {!canContinue && <Alert className="mb-4" type="warning" title={t("ddns.renameInterfaceUnavailable")} showIcon />}
      {error && <Alert className="mb-4" type="error" title={error} showIcon />}
      <Space wrap>
        {candidate && (
          <Button type="primary" disabled={busy} onClick={() => onConfirmRecord(candidate)}>
            {t("ddns.confirmNewRecord")}
          </Button>
        )}
        <Button type={candidate ? "default" : "primary"} disabled={busy || !canContinue} onClick={onCheck}>
          {t(rename.submitted ? "ddns.confirmRename" : "ddns.continueRename")}
        </Button>
        <Button disabled={busy} onClick={onCancel}>
          {t("ddns.cancelRename")}
        </Button>
      </Space>
    </>
  );
}
