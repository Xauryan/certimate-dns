import { useTranslation } from "react-i18next";
import { IconBook, IconBrandGithub, IconMessageChatbot } from "@tabler/icons-react";
import { Badge, Button, Divider, List, Tooltip, Typography } from "antd";

import { APP_DOCUMENT_URL, APP_REPO_URL, APP_VERSION } from "@/domain/app";
import { useVersionChecker } from "@/hooks";

const SettingsAbout = () => {
  const { t } = useTranslation();

  const updateUrl = useVersionChecker();

  return (
    <>
      <h2>Certimate DNS</h2>
      <div className="mb-4">
        <div className="flex items-center gap-2">
          <Typography.Text type="secondary">Version: {APP_VERSION}</Typography.Text>
          {updateUrl && (
            <a href={updateUrl} target="_blank" rel="noopener noreferrer">
              <Badge count={t("settings.about.version.new")} />
            </a>
          )}
        </div>
      </div>
      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Tooltip title={t("settings.about.socials.document")}>
          <Button
            type="text"
            aria-label={t("settings.about.socials.document")}
            icon={<IconBook size="1.5em" />}
            href={APP_DOCUMENT_URL}
            target="_blank"
            rel="noopener noreferrer"
          />
        </Tooltip>
        <Tooltip title={t("settings.about.socials.github")}>
          <Button
            type="text"
            aria-label={t("settings.about.socials.github")}
            icon={<IconBrandGithub size="1.5em" />}
            href={APP_REPO_URL}
            target="_blank"
            rel="noopener noreferrer"
          />
        </Tooltip>
      </div>

      <Divider />

      <h2>{t("settings.about.contributors.title")}</h2>
      <div className="mb-4">
        <Typography.Text type="secondary">{t("settings.about.contributors.tips")}</Typography.Text>
      </div>
      <div className="mb-2 md:max-w-160">
        <img className="max-w-full" src="https://contrib.rocks/image?repo=certimate-go/certimate" alt="Contributors" />
      </div>

      <Divider />

      <div className="md:max-w-160">
        <List bordered>
          <List.Item
            extra={
              <Button href={`${APP_REPO_URL}/issues`} target="_blank" rel="noopener noreferrer">
                {t("settings.about.feedback.button")}
              </Button>
            }
          >
            <List.Item.Meta
              avatar={<IconMessageChatbot size="1.5em" />}
              title={t("settings.about.feedback.title")}
              description={t("settings.about.feedback.subtitle")}
            />
          </List.Item>
        </List>
      </div>
    </>
  );
};

export default SettingsAbout;
