package nginxproxymanager

import "encoding/json"

type sdkResponseBase struct {
	Error json.RawMessage `json:"error"`
}

// Successful results can omit the error field or use an empty value. The
// failure payload may contain request data and must never appear in errors.
func (r *sdkResponseBase) hasError() bool {
	switch string(r.Error) {
	case "", "null", "false", `""`, "0":
		return false
	default:
		return true
	}
}

// GetError reports the response error without embedding provider-controlled text.
// It is promoted by SDK responses that embed sdkResponseBase.
func (r *sdkResponseBase) GetError() string {
	if r != nil && r.hasError() {
		return "NPM returned an API error"
	}
	return ""
}
