import { useRequest } from "ahooks";

import { APP_VERSION } from "@/domain/app";
import { RELEASE_CACHE_KEY, fetchUpdate, readCachedUpdate } from "@/domain/appRelease";

const checkUpdate = () => fetchUpdate(APP_VERSION, localStorage);

const useVersionChecker = () => {
  const { data } = useRequest(checkUpdate, {
    cacheKey: RELEASE_CACHE_KEY,
    staleTime: 15 * 60 * 1000,
    cacheTime: 6 * 60 * 60 * 1000,
    refreshOnWindowFocus: true,
    focusTimespan: 15 * 60 * 1000,
    pollingInterval: 6 * 60 * 60 * 1000,
  });

  return data === undefined ? readCachedUpdate(APP_VERSION, localStorage) : data;
};

export default useVersionChecker;
