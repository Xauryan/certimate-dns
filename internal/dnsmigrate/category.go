package dnsmigrate

import "github.com/pocketbase/dbx"

func (p *planner) categories() (map[int64]Item, error) {
	categories := map[int64]Item{}
	names := map[string]bool{}
	for _, row := range p.manifest.Related {
		if row.Kind != "domain_category" {
			continue
		}
		item := p.item(row.Kind, row.ID, row)
		id, exists, err := p.scalar("SELECT id FROM dnsCategory WHERE name={:name}", dbx.Params{"name": row.CategoryName})
		if err != nil {
			return nil, err
		}
		switch {
		case names[row.CategoryName]:
			item.conflict("duplicate source category name")
		case exists:
			item.Target = id
			item.Action = "reuse"
		default:
			_, collision, err := p.scalar("SELECT id FROM dnsCategory WHERE id={:id}", dbx.Params{"id": item.Target})
			if err != nil {
				return nil, err
			}
			if collision {
				item.conflict("category ID collision or category renamed")
			} else {
				item.Action = "createCategory"
			}
		}
		names[row.CategoryName] = true
		if err := p.finish(&item, exists); err != nil {
			return nil, err
		}
		categories[row.ID] = item
	}
	return categories, nil
}
