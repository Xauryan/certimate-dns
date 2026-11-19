package btpanelgo

import (
	"encoding/json"
)

type sdkResponse interface {
	GetStatus() json.RawMessage
	GetMessage() *string
}

type sdkResponseBase struct {
	Status  json.RawMessage `json:"status,omitempty"`
	Code    *int            `json:"code,omitempty"`
	Message *string         `json:"msg,omitempty"`
}

func (r *sdkResponseBase) GetStatus() json.RawMessage {
	return r.Status
}

func (r *sdkResponseBase) GetMessage() *string {
	return r.Message
}

var _ sdkResponse = (*sdkResponseBase)(nil)

// Confirmed recognizes the bool and numeric status formats used by the Windows panel.
func (r *sdkResponseBase) Confirmed() bool {
	return string(r.Status) == "true" || string(r.Status) == "0"
}
