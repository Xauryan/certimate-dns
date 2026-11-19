import { getPocketBase } from "./_pocketbase";

const pb = getPocketBase();

export const siteThemes = ["light", "dark", "system"] as const;

export type SiteTheme = (typeof siteThemes)[number];

export const isSiteTheme = (value: unknown): value is SiteTheme => siteThemes.some((theme) => theme === value);

export const getSiteAppearance = async () => {
  const appearance = await pb.send<{ theme: SiteTheme }>("/api/appearance", { headers: { Authorization: "" }, requestKey: null });
  if (!isSiteTheme(appearance?.theme)) throw new Error("Invalid site appearance");
  return appearance;
};

export const saveSiteAppearance = (theme: SiteTheme) => pb.send<{ theme: SiteTheme }>("/api/appearance", { method: "PUT", body: { theme }, requestKey: null });

export const listCronJobs = () => {
  return pb.crons
    .getFullList({
      requestKey: null,
    })
    .then((res) => {
      const jobs = res
        .filter((job) => !job.id.startsWith("__pb"))
        .map((job) => {
          return {
            id: job.id,
            cron: job.expression,
          };
        });
      return {
        items: jobs,
      };
    });
};

export type ListLogsRequest = {
  page?: number;
  perPage?: number;
};

export const listLogs = (request: ListLogsRequest) => {
  const page = request.page || 1;
  const perPage = request.perPage || 10;

  return pb.logs
    .getList(page, perPage, {
      filter: 'data.type!="request"',
      sort: "-@rowid",
      skipTotal: true,
      requestKey: null,
    })
    .then((res) => {
      return {
        items: res.items,
      };
    });
};
