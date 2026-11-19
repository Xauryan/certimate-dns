package migrations

import (
	"errors"

	"github.com/certimate-go/certimate/internal/dnsautomation"
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(dnsautomation.Install, func(core.App) error { return errors.ErrUnsupported })
}
