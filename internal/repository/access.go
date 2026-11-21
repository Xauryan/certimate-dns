package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"github.com/certimate-go/certimate/internal/app"
	"github.com/certimate-go/certimate/internal/domain"
)

type AccessRepository struct {
	app core.App
}

func NewAccessRepository() *AccessRepository {
	return NewAccessRepositoryFor(app.GetApp())
}

func NewAccessRepositoryFor(app core.App) *AccessRepository {
	return &AccessRepository{app: app}
}

func (r *AccessRepository) GetById(ctx context.Context, id string) (*domain.Access, error) {
	record, err := r.app.FindRecordById(domain.CollectionNameAccess, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrRecordNotFound
		}
		return nil, err
	}

	if !record.GetDateTime("deleted").Time().IsZero() {
		return nil, domain.ErrRecordNotFound
	}

	return r.castRecordToModel(record)
}

func (r *AccessRepository) castRecordToModel(record *core.Record) (*domain.Access, error) {
	if record == nil {
		return nil, fmt.Errorf("the record is nil")
	}

	config := make(map[string]any)
	if err := record.UnmarshalJSONField("config", &config); err != nil {
		return nil, fmt.Errorf("field 'config' is malformed")
	}

	access := &domain.Access{
		Meta: domain.Meta{
			Id:        record.Id,
			CreatedAt: record.GetDateTime("created").Time(),
			UpdatedAt: record.GetDateTime("updated").Time(),
		},
		Name:     record.GetString("name"),
		Provider: record.GetString("provider"),
		Config:   config,
		Reserve:  record.GetString("reserve"),
	}
	return access, nil
}

// CreateDNSCredential creates an access record with the same name and
// provider identity checks used when managing DNS accounts.
func (r *AccessRepository) CreateDNSCredential(ctx context.Context, access *domain.Access) (*domain.Access, error) {
	var created *domain.Access
	err := r.app.RunInTransaction(func(tx core.App) error {
		collection, err := tx.FindCollectionByNameOrId(domain.CollectionNameAccess)
		if err != nil {
			return err
		}
		_, err = tx.FindFirstRecordByFilter(collection, "provider={:provider} && name={:name} && reserve='' && deleted=''",
			dbx.Params{"provider": access.Provider, "name": access.Name})
		if err == nil {
			return domain.NewError(409, "DNS credential name already exists for this provider")
		}
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		record := core.NewRecord(collection)
		record.Set("name", access.Name)
		record.Set("provider", access.Provider)
		record.Set("config", access.Config)
		if err := tx.SaveWithContext(ctx, record); err != nil {
			return err
		}
		created, err = r.castRecordToModel(record)
		return err
	})
	return created, err
}

func (r *AccessRepository) Save(ctx context.Context, access *domain.Access) (*domain.Access, error) {
	collection, err := r.app.FindCollectionByNameOrId(domain.CollectionNameAccess)
	if err != nil {
		return access, err
	}

	if access.Id == "" {
		return access, domain.ErrRecordNotFound
	}

	record, err := r.app.FindRecordById(collection, access.Id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return access, domain.ErrRecordNotFound
		}
		return access, err
	}

	record.Set("name", access.Name)
	record.Set("provider", access.Provider)
	record.Set("config", access.Config)
	record.Set("reserve", access.Reserve)
	if access.DeletedAt != nil {
		record.Set("deleted", access.DeletedAt)
	}
	if err := r.app.Save(record); err != nil {
		return access, err
	}

	access.Id = record.Id
	access.CreatedAt = record.GetDateTime("created").Time()
	access.UpdatedAt = record.GetDateTime("updated").Time()
	return access, nil
}
