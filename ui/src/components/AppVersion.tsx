import { Badge, Typography } from "antd";

import { APP_DOWNLOAD_URL, APP_VERSION } from "@/domain/app";
import { useVersionChecker } from "@/hooks";

interface AppVersionProps {
  className?: string;
  style?: React.CSSProperties;
  children?: React.ReactNode;
}

const AppVersion = ({ className, style, children }: AppVersionProps) => {
  const updateUrl = useVersionChecker();

  return (
    <Badge
      styles={{
        indicator: { transform: "scale(0.75) translate(50%, -85%)" },
      }}
      count={updateUrl ? "NEW" : void 0}
    >
      {children ?? (
        <Typography.Link className={className} style={style} type="secondary" href={updateUrl ?? APP_DOWNLOAD_URL} target="_blank" rel="noopener noreferrer">
          {APP_VERSION}
        </Typography.Link>
      )}
    </Badge>
  );
};

export default AppVersion;
