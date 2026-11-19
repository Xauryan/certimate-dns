import { useTranslation } from "react-i18next";
import { IconMoon, type IconProps, IconSun, IconSunMoon, IconWorld } from "@tabler/icons-react";
import { Button, Dropdown, type DropdownProps } from "antd";

import Show from "@/components/Show";
import { useBrowserTheme } from "@/hooks";
import { type BrowserTheme } from "@/hooks/useBrowserTheme";

export const useAppThemeMenuItems = () => {
  const { t } = useTranslation();

  const { setThemeMode } = useBrowserTheme();

  const items = (
    [
      ["site", "common.theme.site", <IconWorld size="1em" />],
      ["light", "common.theme.light", <IconSun size="1em" />],
      ["dark", "common.theme.dark", <IconMoon size="1em" />],
      ["system", "common.theme.system", <IconSunMoon size="1em" />],
    ] satisfies Array<[BrowserTheme, string, React.ReactNode]>
  ).map(([key, label, icon]) => {
    return {
      key: key,
      label: t(label),
      icon: icon,
      onClick: () => setThemeMode(key),
    };
  });

  return items;
};

export interface AppThemeDropdownProps {
  children?: React.ReactNode;
  trigger?: DropdownProps["trigger"];
}

const AppThemeDropdown = ({ children, trigger = ["click"] }: AppThemeDropdownProps) => {
  const items = useAppThemeMenuItems();

  return (
    <Dropdown menu={{ items }} trigger={trigger}>
      {children}
    </Dropdown>
  );
};

export interface AppThemeIconProps extends IconProps {}

const AppThemeIcon = (props: AppThemeIconProps) => {
  const { theme } = useBrowserTheme();

  return (
    <Show>
      <Show.Case when={theme === "dark"}>
        <IconMoon {...props} />
      </Show.Case>
      <Show.Default>
        <IconSun {...props} />
      </Show.Default>
    </Show>
  );
};

export interface AppThemeLinkButtonProps {
  className?: string;
  style?: React.CSSProperties;
  showIcon?: boolean;
}

const AppThemeLinkButton = ({ className, style, showIcon = true }: AppThemeLinkButtonProps) => {
  const { t } = useTranslation();

  const { themeMode } = useBrowserTheme();

  return (
    <AppThemeDropdown>
      <Button
        className={className}
        style={style}
        size="small"
        type="text"
        aria-label={`${t("settings.appearance.theme.title")}: ${t(`common.theme.${themeMode}`)}`}
        icon={showIcon ? <AppThemeIcon size="1em" /> : undefined}
      >
        {t(`common.theme.${themeMode}`)}
      </Button>
    </AppThemeDropdown>
  );
};

export default {
  Dropdown: AppThemeDropdown,
  Icon: AppThemeIcon,
  LinkButton: AppThemeLinkButton,
};
