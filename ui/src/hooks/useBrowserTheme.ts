import { createContext, useContext } from "react";
import { useLocalStorageState, useRequest, useTheme } from "ahooks";

import { type SiteTheme, getSiteAppearance, isSiteTheme, saveSiteAppearance } from "@/repository/system";

const LOCAL_STORAGE_KEY = "certimate-ui-theme";

export type BrowserTheme = SiteTheme | "site";

export const useBrowserAppearance = () => {
  const [preference, setThemeMode] = useLocalStorageState<BrowserTheme>(LOCAL_STORAGE_KEY, {
    defaultValue: "site",
    serializer: String,
    deserializer: (value) => (isSiteTheme(value) ? value : "site"),
    listenStorageChange: true,
  });
  const siteAppearance = useRequest(getSiteAppearance, {
    refreshOnWindowFocus: true,
    focusTimespan: 30_000,
    onError: () => {},
  });
  const { theme: systemTheme } = useTheme();
  const themeMode = preference ?? "site";
  const effectiveMode = themeMode === "site" ? (siteAppearance.data?.theme ?? "dark") : themeMode;

  const setSiteTheme = async (value: SiteTheme) => {
    const appearance = await saveSiteAppearance(value);
    siteAppearance.cancel();
    siteAppearance.mutate(appearance);
  };

  return { theme: effectiveMode === "system" ? systemTheme : effectiveMode, themeMode, setThemeMode, siteAppearance, setSiteTheme };
};

export const BrowserAppearanceContext = createContext<ReturnType<typeof useBrowserAppearance> | undefined>(undefined);

const useBrowserTheme = () => {
  const value = useContext(BrowserAppearanceContext);
  if (!value) throw new Error("Browser appearance context is missing");
  return value;
};

export default useBrowserTheme;
