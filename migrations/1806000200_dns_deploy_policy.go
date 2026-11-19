package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		_, err := app.DB().NewQuery(`ALTER TABLE dns_cert_deploy ADD COLUMN automatic INTEGER NOT NULL DEFAULT 0;
		ALTER TABLE dns_cert_deploy ADD COLUMN renewal_root TEXT NOT NULL DEFAULT '';
		ALTER TABLE dns_cert_deploy ADD COLUMN automatic_approved INTEGER NOT NULL DEFAULT 0;
		CREATE TRIGGER dns_deploy_revoke_workflow_approval AFTER UPDATE OF graphContent,enabled,hasContent ON workflow
		WHEN OLD.graphContent IS NOT NEW.graphContent OR OLD.enabled IS NOT NEW.enabled OR OLD.hasContent IS NOT NEW.hasContent
		BEGIN
			UPDATE dns_cert_deploy SET automatic_approved=0 WHERE workflow_id=OLD.id AND automatic_approved=1;
		END;
		CREATE TRIGGER dns_deploy_revoke_access_approval AFTER UPDATE OF config,provider,deleted,reserve ON access
		WHEN OLD.config IS NOT NEW.config OR OLD.provider IS NOT NEW.provider OR OLD.deleted IS NOT NEW.deleted OR OLD.reserve IS NOT NEW.reserve
		BEGIN
			UPDATE dns_cert_deploy SET automatic_approved=0 WHERE access_id=OLD.id AND automatic_approved=1;
		END;
		CREATE INDEX dns_cert_deploy_automatic ON dns_cert_deploy(id) WHERE active=1 AND automatic=1;
		CREATE TABLE dns_cert_deploy_attempts (
			id TEXT PRIMARY KEY,
			task_id TEXT NOT NULL,
			order_id TEXT NOT NULL,
			certificate_id TEXT NOT NULL,
			domain TEXT NOT NULL,
			access_id TEXT NOT NULL,
			workflow_id TEXT NOT NULL,
			node_id TEXT NOT NULL,
			provider TEXT NOT NULL,
			trigger TEXT NOT NULL,
			started INTEGER NOT NULL,
			finished INTEGER NOT NULL DEFAULT 0,
			outcome TEXT NOT NULL
		);
		CREATE INDEX dns_cert_deploy_attempts_task ON dns_cert_deploy_attempts(task_id,started DESC)`).Execute()
		return err
	}, func(app core.App) error {
		_, err := app.DB().NewQuery(`DROP TABLE dns_cert_deploy_attempts;
		DROP INDEX dns_cert_deploy_automatic;
		DROP TRIGGER dns_deploy_revoke_workflow_approval;
		DROP TRIGGER dns_deploy_revoke_access_approval;
		ALTER TABLE dns_cert_deploy DROP COLUMN automatic_approved;
		ALTER TABLE dns_cert_deploy DROP COLUMN renewal_root;
		ALTER TABLE dns_cert_deploy DROP COLUMN automatic`).Execute()
		return err
	})
}
