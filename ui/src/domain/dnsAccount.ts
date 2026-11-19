import { ACCESS_PROVIDERS } from "./provider";

// Credential types use Certimate IDs; labels identify the DNS product operated by each driver.
export const dnsAccountProviderLabels: ReadonlyMap<string, string> = new Map([
  [ACCESS_PROVIDERS.ALIYUN, "dns.providers.aliyun"],
  [ACCESS_PROVIDERS.ALIYUNESA, "provider.aliyun_esa"],
  [ACCESS_PROVIDERS.AWS, "provider.aws_route53"],
  [ACCESS_PROVIDERS.BAIDUCLOUD, "provider.baiducloud_dns"],
  [ACCESS_PROVIDERS.BT, "provider.bt"],
  [ACCESS_PROVIDERS.CLOUDFLARE, "dns.providers.cloudflare"],
  [ACCESS_PROVIDERS.DNSLA, "provider.dnsla"],
  [ACCESS_PROVIDERS.DNSMGR, "provider.dnsmgr"],
  [ACCESS_PROVIDERS.DYNV6, "provider.dynv6"],
  [ACCESS_PROVIDERS.GOEDGE, "provider.goedge"],
  [ACCESS_PROVIDERS.HENET, "provider.henet"],
  [ACCESS_PROVIDERS.HUAWEICLOUD, "provider.huaweicloud_dns"],
  [ACCESS_PROVIDERS.JDCLOUD, "provider.jdcloud_dns"],
  [ACCESS_PROVIDERS.NAMESILO, "provider.namesilo"],
  [ACCESS_PROVIDERS.POWERDNS, "provider.powerdns"],
  [ACCESS_PROVIDERS.QINGCLOUD, "provider.qingcloud_dns"],
  [ACCESS_PROVIDERS.SPACESHIP, "provider.spaceship"],
  [ACCESS_PROVIDERS.TECHNITIUMDNS, "provider.technitiumdns"],
  [ACCESS_PROVIDERS.TENCENTCLOUD, "dns.providers.tencentcloud"],
  [ACCESS_PROVIDERS.TENCENTEO, "provider.tencentcloud_eo"],
  [ACCESS_PROVIDERS.VOLCENGINE, "provider.volcengine_dns"],
  [ACCESS_PROVIDERS.WESTCN, "provider.westcn"],
]);

/** Retain settings belonging to other consumers of this shared credential. */
export function mergeDNSAccountConfig(provider: string, original: Record<string, unknown> = {}, edited: Record<string, unknown> = {}) {
  const config = { ...original, ...edited };
  if (provider === ACCESS_PROVIDERS.CLOUDFLARE && config.authMethod === "globalapikey") {
    delete config.apiToken;
    delete config.apiTokenForZone;
  } else if (provider === ACCESS_PROVIDERS.CLOUDFLARE && original.authMethod === "globalapikey") {
    delete config.email;
    delete config.apiKey;
  }
  if (provider === ACCESS_PROVIDERS.AWS && config.authMethod === "imds") {
    delete config.accessKeyId;
    delete config.secretAccessKey;
  }
  if (provider === ACCESS_PROVIDERS.GOEDGE && config.apiRole === "user") {
    delete config.userId;
  }
  return config;
}
