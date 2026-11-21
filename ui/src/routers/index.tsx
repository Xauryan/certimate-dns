import { createHashRouter } from "react-router-dom";

import AccessList from "@/pages/accesses/AccessList";
import AccessNew from "@/pages/accesses/AccessNew";
import AuthLayout from "@/pages/AuthLayout";
import CertificateList from "@/pages/certificates/CertificateList";
import CloudflareManager from "@/pages/cfmanagement/CloudflareManager";
import ConsoleLayout from "@/pages/ConsoleLayout";
import Dashboard from "@/pages/dashboard/Dashboard";
import DNSDDNS from "@/pages/ddns/DNSDDNS";
import DNSManager from "@/pages/dns/DNSManager";
import DNSMember from "@/pages/dnsauth/DNSMember";
import DNSPermissions from "@/pages/dnsauth/DNSPermissions";
import DNSAutomation from "@/pages/dnsautomation/DNSAutomation";
import DomainCatalog from "@/pages/dnscatalog/DomainCatalog";
import CertificateOrders from "@/pages/dnscert";
import CertificateDeployments from "@/pages/dnscert/CertificateDeployments";
import DNSIdentity from "@/pages/dnsidentity/DNSIdentity";
import DNSInterfaceKeys from "@/pages/dnsinterfaces/DNSInterfaceKeys";
import ErrorLayout from "@/pages/ErrorLayout";
import Login from "@/pages/login/Login";
import PresetList from "@/pages/presets/PresetList";
import Settings from "@/pages/settings/Settings";
import SettingsAbout from "@/pages/settings/SettingsAbout";
import SettingsAccount from "@/pages/settings/SettingsAccount";
import SettingsAppearance from "@/pages/settings/SettingsAppearance";
import SettingsDiagnostics from "@/pages/settings/SettingsDiagnostics";
import SettingsDNSProxy from "@/pages/settings/SettingsDNSProxy";
import SettingsPersistence from "@/pages/settings/SettingsPersistence";
import SettingsSSLProvider from "@/pages/settings/SettingsSSLProvider";
import WorkflowDetail from "@/pages/workflows/WorkflowDetail";
import WorkflowDetailDesign from "@/pages/workflows/WorkflowDetailDesign";
import WorkflowDetailRuns from "@/pages/workflows/WorkflowDetailRuns";
import WorkflowList from "@/pages/workflows/WorkflowList";
import WorkflowNew from "@/pages/workflows/WorkflowNew";

export const router = createHashRouter([
  {
    path: "/",
    element: <ConsoleLayout />,
    children: [
      {
        path: "/",
        element: <Dashboard />,
      },
      { path: "/dns", element: <DNSManager /> },
      { path: "/dns/catalog", element: <DomainCatalog /> },
      { path: "/dns/cloudflare", element: <CloudflareManager /> },
      { path: "/dns/automation", element: <DNSAutomation /> },
      { path: "/dns/ddns", element: <DNSDDNS /> },
      { path: "/dns-automation", element: <DNSAutomation /> },
      { path: "/dns-cert", element: <CertificateOrders /> },
      { path: "/dns-cert/deployments", element: <CertificateDeployments /> },
      { path: "/dns-permissions", element: <DNSPermissions /> },
      { path: "/dns-identity", element: <DNSIdentity /> },
      {
        path: "/dns-interfaces",
        element: (
          <main className="p-4 md:p-6">
            <DNSInterfaceKeys />
          </main>
        ),
      },
      {
        path: "/accesses",
        element: <AccessList />,
      },
      {
        path: "/accesses/new",
        element: <AccessNew />,
      },
      {
        path: "/certificates",
        element: <CertificateList />,
      },
      {
        path: "/workflows",
        element: <WorkflowList />,
      },
      {
        path: "/workflows/new",
        element: <WorkflowNew />,
      },
      {
        path: "/workflows/:id",
        element: <WorkflowDetail />,
        children: [
          {
            path: "/workflows/:id/design",
            element: <WorkflowDetailDesign />,
          },
          {
            path: "/workflows/:id/runs",
            element: <WorkflowDetailRuns />,
          },
        ],
      },
      {
        path: "/presets",
        element: <PresetList />,
      },
      {
        path: "/settings",
        element: <Settings />,
        children: [
          {
            path: "/settings/account",
            element: <SettingsAccount />,
          },
          {
            path: "/settings/appearance",
            element: <SettingsAppearance />,
          },
          {
            path: "/settings/ssl-provider",
            element: <SettingsSSLProvider />,
          },
          {
            path: "/settings/persistence",
            element: <SettingsPersistence />,
          },
          {
            path: "/settings/dns-proxy",
            element: <SettingsDNSProxy />,
          },
          {
            path: "/settings/diagnostics",
            element: <SettingsDiagnostics />,
          },
          {
            path: "/settings/about",
            element: <SettingsAbout />,
          },
        ],
      },
    ],
  },
  { path: "/dns-member", element: <DNSMember /> },
  {
    path: "/login",
    element: <AuthLayout />,
    children: [
      {
        path: "/login",
        element: <Login />,
      },
    ],
  },
  {
    path: "*",
    element: (
      <ErrorLayout>
        <div className="flex h-screen w-full flex-col items-center justify-center">
          <div className="flex flex-wrap items-center justify-center gap-x-4 gap-y-2">
            <h1>404</h1>
            <h2>This page could not be found.</h2>
          </div>
        </div>
      </ErrorLayout>
    ),
  },
]);
