package nvd

import (
	"context"
	"time"

	"holmes/internal/cache"
	"holmes/internal/model"
	"holmes/internal/service/adapters"
)

type Detective struct {
	nvd   *adapters.NVDAdapter
	store cache.DomainStore
}

func New(nvd *adapters.NVDAdapter, store cache.DomainStore) *Detective {
	return &Detective{nvd: nvd, store: store}
}

func (d *Detective) Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "nvd", Status: model.StatusSuccess}

	cpes := collectCPEs(clues)
	if len(cpes) == 0 {
		inv.Status = model.StatusSkipped
		inv.Error = "no CPEs available for NVD lookup"
		return inv, nil
	}

	seen := map[string]bool{}
	var found []model.Vulnerability

	for _, cpe := range cpes {
		// Short-circuit: use domain cache when available.
		if d.store != nil {
			if ids, ok, _ := d.store.GetCPEQuery(ctx, cpe); ok {
				for _, id := range ids {
					if seen[id] {
						continue
					}
					seen[id] = true
					if v, _ := d.store.GetVulnByOrigin(ctx, id, "nvd"); v != nil {
						found = append(found, *v)
					}
				}
				continue
			}
		}

		// Fetch from NVD API.
		vulns, err := d.nvd.QueryByCPE(ctx, cpe)
		if err != nil {
			inv.Status = model.StatusFailed
			inv.Error = err.Error()
			return inv, nil
		}

		ids := make([]string, 0, len(vulns))
		for _, v := range vulns {
			if v.ID == "" {
				continue
			}
			ids = append(ids, v.ID)
			if seen[v.ID] {
				continue
			}
			seen[v.ID] = true
			found = append(found, v)
		}

		// Persist to domain cache.
		if d.store != nil {
			if len(vulns) > 0 {
				_ = d.store.SaveVulns(ctx, vulns, 24*time.Hour)
			}
			_ = d.store.SaveCPEQuery(ctx, cpe, ids, 24*time.Hour)
		}
	}

	clues.Vulnerabilities = append(clues.Vulnerabilities, found...)
	inv.Result = map[string]int{"count": len(found)}
	return inv, nil
}

// collectCPEs returns a deduplicated list of CPE strings to query.
// The input CPE (clues.CPE) is first; PackageData CPEs follow.
func collectCPEs(clues *model.Clues) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(cpe string) {
		if cpe == "" {
			return
		}
		if _, ok := seen[cpe]; ok {
			return
		}
		seen[cpe] = struct{}{}
		out = append(out, cpe)
	}
	add(clues.CPE)
	if clues.PackageData != nil {
		for _, cpe := range clues.PackageData.CPEs {
			add(cpe)
		}
	}
	return out
}
