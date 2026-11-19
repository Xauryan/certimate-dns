import { memo, useCallback, useState, useSyncExternalStore } from "react";
import { useTranslation } from "react-i18next";
import { Navigate, Outlet, useLocation, useNavigate } from "react-router-dom";
import {
  IconBrandGithub,
  IconCertificate,
  IconCodeDots,
  IconFingerprint,
  IconHelpCircle,
  IconHierarchy3,
  IconHome,
  IconLayoutSidebarLeftCollapse,
  IconLayoutSidebarRightCollapse,
  IconMenu2,
  IconPower,
  IconSettings,
  IconWorld,
} from "@tabler/icons-react";
import { Alert, Button, Drawer, Layout, Menu, type MenuProps, theme } from "antd";

import AppLocale from "@/components/AppLocale";
import AppTheme from "@/components/AppTheme";
import AppVersion from "@/components/AppVersion";
import Show from "@/components/Show";
import { APP_DOCUMENT_URL, APP_REPO_URL } from "@/domain/app";
import { useTriggerElement } from "@/hooks";
import { getAuthStore } from "@/repository/admin";
import { isBrowserHappy } from "@/utils/browser";
import { withBasePath } from "@/utils/url";

const subscribeToAuth = (notify: () => void) => getAuthStore().onChange(notify);
const currentToken = () => getAuthStore().token;

const ConsoleLayout = () => {
  useSyncExternalStore(subscribeToAuth, currentToken);
  const navigate = useNavigate();

  const { t } = useTranslation();

  const { token: themeToken } = theme.useToken();

  const [siderCollapsed, setSiderCollapsed] = useState(false);

  const handleLogoutClick = () => {
    auth.clear();
    navigate("/login");
  };

  const handleDocumentClick = () => {
    window.open(APP_DOCUMENT_URL, "_blank");
  };

  const handleGitHubClick = () => {
    window.open(APP_REPO_URL, "_blank");
  };

  const auth = getAuthStore();
  if (!auth.isValid || !auth.isSuperuser) {
    const member = auth.isValid && ["dns_members", "dns_zone_sessions"].includes(auth.record?.collectionName ?? "");
    return <Navigate replace to={member ? "/dns-member" : "/login"} />;
  }

  return (
    <Layout className="h-screen bg-background text-foreground">
      <Show when={!isBrowserHappy()}>
        <Alert banner closable showIcon title={t("common.text.happy_browser")} type="warning" />
      </Show>

      <Layout className="h-screen" hasSider>
        <Layout.Sider
          className="group/sider z-20 h-full border-r bg-background max-md:static max-md:hidden"
          style={{ borderColor: themeToken.colorBorderSecondary }}
          theme="light"
          width={siderCollapsed ? 81 : 256}
        >
          <div className="flex size-full flex-col items-center justify-between overflow-hidden select-none">
            <div className="min-h-0 w-full flex-1 overflow-y-auto px-2">
              <SiderMenu collapsed={siderCollapsed} />
            </div>
            <div className="w-full shrink-0 px-2 pb-2">
              <Menu
                style={{ background: "transparent", borderInlineEnd: "none" }}
                inlineCollapsed={siderCollapsed}
                items={[
                  {
                    key: "document",
                    icon: (
                      <span className="anticon scale-125" role="img">
                        <IconHelpCircle size="1em" />
                      </span>
                    ),
                    label: t("common.menu.gethelp"),
                    onClick: handleDocumentClick,
                  },
                  {
                    key: "logout",
                    danger: true,
                    icon: (
                      <span className="anticon scale-125" role="img">
                        <IconPower size="1em" />
                      </span>
                    ),
                    label: t("common.menu.logout"),
                    onClick: handleLogoutClick,
                  },
                ]}
                mode="vertical"
                selectable={false}
              />
            </div>
          </div>
          <div className="absolute top-1/2 right-0 translate-x-1/2 -translate-y-1/2 opacity-0 transition-opacity group-hover/sider:opacity-100">
            <Button
              className="bg-background shadow-sm"
              icon={
                siderCollapsed ? (
                  <IconLayoutSidebarRightCollapse size="1.5em" stroke="1.25" color="#999" />
                ) : (
                  <IconLayoutSidebarLeftCollapse size="1.5em" stroke="1.25" color="#999" />
                )
              }
              shape="circle"
              type="text"
              onClick={() => setSiderCollapsed(!siderCollapsed)}
            />
          </div>
        </Layout.Sider>

        <Layout className="flex flex-col overflow-hidden">
          <Layout.Header
            className="relative border-b shadow-sm md:hidden"
            style={{
              padding: 0,
              borderBottomColor: themeToken.colorBorderSecondary,
            }}
          >
            <div className="absolute inset-0 z-0">
              <div
                className="size-full"
                style={{
                  backgroundImage:
                    "linear-gradient(rgba(255, 255, 255, 0.063) 1px, transparent 1px), linear-gradient(90deg, rgba(255, 255, 255, 0.063) 1px, transparent 1px)",
                  backgroundSize: "20px 20px",
                }}
              >
                <div className="size-full backdrop-blur-[1px]"></div>
              </div>
            </div>
            <div className="flex size-full items-center justify-between overflow-hidden px-4">
              <div className="flex items-center gap-4">
                <SiderMenuDrawer trigger={<Button aria-label={t("dns.navigation")} icon={<IconMenu2 size="1.25em" stroke="1.25" />} />} />
              </div>
              <div className="flex size-full grow items-center justify-end gap-4 overflow-hidden">
                <AppTheme.Dropdown>
                  <Button icon={<AppTheme.Icon size="1.25em" stroke="1.25" />} />
                </AppTheme.Dropdown>
                <AppLocale.Dropdown>
                  <Button icon={<AppLocale.Icon size="1.25em" stroke="1.25" />} />
                </AppLocale.Dropdown>
                <AppVersion>
                  <Button icon={<IconBrandGithub size="1.25em" stroke="1.25" />} onClick={handleGitHubClick} />
                </AppVersion>
                <Button danger icon={<IconPower size="1.25em" stroke="1.25" />} onClick={handleLogoutClick} />
              </div>
            </div>
          </Layout.Header>

          <Layout.Content className="relative flex-1 overflow-x-hidden overflow-y-auto">
            <Outlet key={auth.record?.id} />
          </Layout.Content>
        </Layout>
      </Layout>
    </Layout>
  );
};

const SiderMenu = memo(({ collapsed, onSelect }: { collapsed?: boolean; onSelect?: (key: string) => void }) => {
  const location = useLocation();
  const navigate = useNavigate();

  const { t } = useTranslation();

  const dnsPages = [
    ["/dns", "dns.records"],
    ["/dns/catalog", "dns.catalog"],
    ["/dns/automation", "dns.automation"],
    ["/dns/cloudflare", "dns.cloudflare"],
    ["/dns-cert", "dns.orders"],
    ["/dns-permissions", "dnsauth.permissions"],
    ["/dns-identity", "dns.identity"],
    ["/dns-interfaces", "dns.interfaces"],
  ];
  const icon = (node: React.ReactNode) => (
    <span className="anticon scale-125" role="img">
      {node}
    </span>
  );
  const item = (key: string, label: string, node: React.ReactNode) => ({ key, label: t(label), icon: icon(node) });
  const menuItems: Required<MenuProps>["items"] = [
    item("/", "dashboard.page.heading", <IconHome size="1em" />),
    item("/workflows", "workflow.page.heading", <IconHierarchy3 size="1em" />),
    item("/certificates", "certificate.page.heading", <IconCertificate size="1em" />),
    {
      ...item("dns-tools", "dns.heading", <IconWorld size="1em" />),
      children: dnsPages.map(([key, label]) => ({ key, label: t(label) })),
    },
    item("/accesses", "access.page.heading", <IconFingerprint size="1em" />),
    item("/presets", "preset.page.heading", <IconCodeDots size="1em" />),
    item("/settings", "settings.page.heading", <IconSettings size="1em" />),
  ];
  const dnsActive = dnsPages.some(([key]) => key === location.pathname);
  const selectedKey = dnsActive ? location.pathname : "/" + (location.pathname.split("/")[1] ?? "");

  return (
    <>
      <div className="h-[64px] w-full overflow-hidden px-4 py-2 max-md:py-0">
        <div className="flex size-full items-center justify-around gap-2">
          <img src={withBasePath("/logo.svg")} className="size-[36px]" />
          <Show when={!collapsed}>
            <span className="w-[81px] truncate text-base leading-[64px] font-semibold">Certimate</span>
            <AppVersion className="text-xs" />
          </Show>
        </div>
      </div>
      <div className="w-full grow overflow-x-hidden overflow-y-auto">
        <Menu
          style={{ background: "transparent", borderInlineEnd: "none" }}
          inlineCollapsed={collapsed}
          items={menuItems}
          mode="inline"
          defaultOpenKeys={dnsActive ? ["dns-tools"] : []}
          selectedKeys={[selectedKey]}
          onClick={({ key }) => {
            navigate(key);
            onSelect?.(key);
          }}
        />
      </div>
    </>
  );
});

const SiderMenuDrawer = memo(({ trigger }: { trigger: React.ReactNode }) => {
  const { token: themeToken } = theme.useToken();

  const [siderOpen, setSiderOpen] = useState(false);

  const triggerEl = useTriggerElement(trigger, { onClick: () => setSiderOpen(true) });

  const handleMenuSelect = useCallback(() => {
    setSiderOpen(false);
  }, []);

  return (
    <>
      {triggerEl}

      <Drawer
        closable={false}
        destroyOnHidden
        open={siderOpen}
        placement="left"
        styles={{
          section: { paddingTop: themeToken.paddingSM, paddingBottom: themeToken.paddingSM },
          body: { padding: 0 },
        }}
        onClose={() => setSiderOpen(false)}
      >
        <SiderMenu onSelect={handleMenuSelect} />
      </Drawer>
    </>
  );
});

export default ConsoleLayout;
