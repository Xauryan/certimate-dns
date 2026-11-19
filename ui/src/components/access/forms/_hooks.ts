import { useMemo } from "react";

import { dnsAccountProviderLabels } from "@/domain/dnsAccount";
import { ACCESS_USAGES, type AccessProvider } from "@/domain/provider";

import type { AccessFormUsages } from "../AccessForm";

export const useProviderFilterByUsage = (usage?: AccessFormUsages) => {
  return useMemo(() => {
    if (usage == null) return;

    switch (usage) {
      case "dns":
        return (_: string, option: AccessProvider) => option.usages.includes(ACCESS_USAGES.DNS);
      case "dns-management":
        return (provider: string) => dnsAccountProviderLabels.has(provider);
      case "hosting":
        return (_: string, option: AccessProvider) => option.usages.includes(ACCESS_USAGES.HOSTING);
      case "dns-hosting":
        return (_: string, option: AccessProvider) => option.usages.includes(ACCESS_USAGES.DNS) || option.usages.includes(ACCESS_USAGES.HOSTING);
      case "ca":
        return (_: string, option: AccessProvider) => option.usages.includes(ACCESS_USAGES.CA);
      case "notification":
        return (_: string, option: AccessProvider) => option.usages.includes(ACCESS_USAGES.NOTIFICATION);
      default:
        console.warn(`[certimate] unsupported provider usage: '${usage}'`);
    }
  }, [usage]);
};
