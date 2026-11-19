import { z } from "zod";

type FieldKind = "text" | "secret" | "https" | "email" | "list" | "port" | "fingerprint" | "positiveId" | "cdnDomainId" | "sniTarget";

export interface HostingField {
  name: string;
  label?: string;
  kind?: FieldKind;
  optional?: boolean;
  help?: string;
  initial?: string | number;
}

const serverUrl: HostingField = { name: "serverUrl", kind: "https" };
const username: HostingField = { name: "username" };
const password: HostingField = { name: "password", kind: "secret" };
const apiKey: HostingField = { name: "apiKey", kind: "secret" };
const securityKey: HostingField = { name: "securityKey", kind: "secret" };
const siteNames: HostingField = { name: "target", label: "siteNames", kind: "list" };
const domains: HostingField = { name: "target", label: "domains", kind: "list" };

export const panelAccessFields = {
  amh: [serverUrl, username, { ...password, help: "amhLogin" }],
  cloudpanel: [serverUrl, username, password],
  directadmin: [serverUrl, username, password],
  fnos: [
    { name: "host" },
    { name: "port", kind: "port", initial: 22 },
    username,
    password,
    { name: "hostKeyFingerprint", kind: "fingerprint", help: "fingerprintHelp" },
  ],
  iis: [
    { name: "host" },
    { name: "port", kind: "port", initial: 22 },
    { ...username, help: "iisSshAccount" },
    password,
    { name: "hostKeyFingerprint", kind: "fingerprint", help: "iisFingerprintHelp" },
  ],
  kangle: [serverUrl, username, { ...password, optional: true, help: "kangleAuth" }, { ...securityKey, optional: true }],
  kangleadmin: [serverUrl, username, securityKey, { name: "adminPath", optional: true, initial: "/admin" }],
  kuocai: [username, password],
  lucky: [serverUrl, { name: "apiToken", kind: "secret" }],
  mwpanel: [serverUrl, { name: "appId" }, { name: "appSecret", kind: "secret" }],
  qzyun: [{ name: "email", kind: "email" }, password],
  uusec: [serverUrl, username, password],
  xp: [serverUrl, apiKey],
} satisfies Record<string, HostingField[]>;

export const panelDeploymentFields = {
  amh: [{ name: "environment" }, siteNames],
  cloudpanel: [domains],
  directadmin: [domains],
  fnos: [],
  iis: [{ name: "target", label: "iisTarget", kind: "sniTarget", help: "iisTargetHelp" }],
  kangle: [{ ...domains, optional: true, help: "kangleDomains" }],
  kangleadmin: [
    { name: "target", label: "siteUsers", kind: "list" },
    { name: "domains", kind: "list", optional: true, help: "kangleAdminDomains" },
  ],
  "kangleadmin-console": [],
  kuocai: [{ name: "target", label: "cdnDomainId", kind: "cdnDomainId" }],
  lucky: [{ ...domains, optional: true, help: "luckyDomains" }],
  mwpanel: [siteNames],
  "mwpanel-console": [],
  qzyun: [
    { name: "target", label: "certificateNameOrId" },
    { name: "domain", label: "bindingDomain", optional: true },
  ],
  "tencentcloud-lighthouse": [
    { name: "region", label: "tencentRegion" },
    { name: "instanceId", label: "tencentInstanceId" },
    { name: "domain", label: "tencentDomain" },
  ],
  "tencentcloud-tcb": [
    { name: "region", label: "tencentRegion" },
    { name: "environmentId", label: "tencentEnvironmentId" },
    { name: "domain", label: "tencentDomain" },
  ],
  "tencentcloud-tke": [{ name: "region" }, { name: "clusterId" }, { name: "namespace" }, { name: "secretName" }],
  uusec: [
    { name: "target", label: "certificateId", kind: "positiveId" },
    { name: "name", label: "certificateName" },
  ],
  "westcn-vhost": [{ name: "target", label: "ftpSite" }],
  xp: [siteNames],
} satisfies Record<string, HostingField[]>;

function fieldSchema(field: HostingField) {
  switch (field.kind) {
    case "port":
      return z.coerce.number().int().min(1).max(65535);
    case "https":
      return z.url({ protocol: /^https$/ }).refine((raw) => {
        if (!URL.canParse(raw)) return false;
        const url = new URL(raw);
        return !url.username && !url.password && !raw.includes("?") && !raw.includes("#");
      });
    case "email":
      return z.email();
    case "fingerprint":
      return z.string().regex(/^SHA256:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]$/);
    case "cdnDomainId":
      return z
        .string()
        .trim()
        .regex(/^[0-9]{1,32}$/);
    case "sniTarget":
      return z
        .string()
        .trim()
        .refine((raw) => {
          const [host, port, extra] = raw.split(":");
          const name = host.replace(/\.$/, "");
          return (
            extra === undefined &&
            name.length <= 253 &&
            name.includes(".") &&
            !/^\d+\.\d+\.\d+\.\d+$/.test(name) &&
            name.split(".").every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label)) &&
            (port === undefined || (/^\d+$/.test(port) && Number(port) > 0 && Number(port) <= 65535))
          );
        });
    case "positiveId":
      return z
        .string()
        .trim()
        .regex(/^[1-9][0-9]*$/);
    default:
      return field.optional ? z.string().nullish() : z.string().trim().min(1);
  }
}

export function panelFieldsSchema(fields: HostingField[], authChoiceMessage: string) {
  const shape = Object.fromEntries(fields.map((field) => [field.name, fieldSchema(field)]));
  return z.object(shape).superRefine((values, ctx) => {
    if (fields === panelAccessFields.kangle && Boolean(values.password) === Boolean(values.securityKey)) {
      for (const path of ["password", "securityKey"]) {
        ctx.addIssue({ code: "custom", path: [path], message: authChoiceMessage });
      }
    }
  });
}
