package pkg

import (
	"context"
	"strings"
	"time"

	"holmes/internal/cache"
	"holmes/internal/model"
	"holmes/internal/service/adapters"
)

type Detective struct {
	eco   *adapters.EcosystemsAdapter
	store cache.DomainStore
}

func New(eco *adapters.EcosystemsAdapter, store cache.DomainStore) *Detective {
	return &Detective{eco: eco, store: store}
}

func (d *Detective) Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "package", Status: model.StatusSuccess}

	// Check domain cache first.
	if d.store != nil {
		term, termEco := lookupTerm(clues)
		if term != "" {
			if pd, err := d.store.FindPackage(ctx, term, termEco); err == nil && pd != nil {
				clues.PackageData = pd
				clues.PURLs = pd.PURLs
				inv.Result = pd
				return inv, nil
			}
		}
	}

	var (
		pd         *model.PackageData
		purls      []string
		advisories []model.Advisory
		err        error
	)
	switch {
	case clues.ResolvedName != "" && clues.Ecosystem != "":
		pd, purls, advisories, err = d.eco.FetchByName(ctx, clues.Ecosystem, clues.ResolvedName)
	case clues.RawName != "" && clues.Ecosystem != "":
		pd, purls, advisories, err = d.eco.FetchByName(ctx, clues.Ecosystem, clues.RawName)
	case clues.PURL != "":
		pd, purls, advisories, err = d.eco.LookupByPURL(ctx, clues.PURL)
	case clues.RepoURL != "":
		pd, purls, advisories, err = d.eco.LookupByRepo(ctx, clues.RepoURL)
	default:
		inv.Status = model.StatusSkipped
		inv.Error = "insufficient clues for package lookup"
		return inv, nil
	}
	_ = advisories
	if err != nil {
		inv.Status = model.StatusFailed
		inv.Error = err.Error()
		return inv, nil
	}

	if d.store != nil && pd != nil {
		terms := buildLookupTerms(clues, pd)
		_ = d.store.SavePackage(ctx, pd, terms, 7*24*time.Hour)
	}

	clues.PackageData = pd
	clues.PURLs = purls
	inv.Result = pd
	return inv, nil
}

// lookupTerm returns the cache lookup key for the current clues state.
func lookupTerm(clues *model.Clues) (string, string) {
	if clues.ResolvedName != "" && clues.Ecosystem != "" {
		return clues.ResolvedName, strings.ToLower(clues.Ecosystem)
	}
	if clues.RawName != "" && clues.Ecosystem != "" {
		return clues.RawName, strings.ToLower(clues.Ecosystem)
	}
	if clues.PURL != "" {
		return clues.PURL, ""
	}
	if clues.RepoURL != "" {
		return clues.RepoURL, ""
	}
	return "", ""
}

// buildLookupTerms collects all identifiers that should resolve to this package.
func buildLookupTerms(clues *model.Clues, pd *model.PackageData) []cache.LookupTerm {
	seen := map[string]struct{}{}
	add := func(term, eco string) []cache.LookupTerm {
		if term == "" {
			return nil
		}
		k := term + "|" + eco
		if _, ok := seen[k]; ok {
			return nil
		}
		seen[k] = struct{}{}
		return []cache.LookupTerm{{Term: term, Ecosystem: eco}}
	}

	var terms []cache.LookupTerm
	terms = append(terms, add(pd.Name, pd.Ecosystem)...)
	if clues.RawName != "" {
		terms = append(terms, add(clues.RawName, strings.ToLower(clues.Ecosystem))...)
	}
	if clues.ResolvedName != "" {
		terms = append(terms, add(clues.ResolvedName, strings.ToLower(clues.Ecosystem))...)
	}
	if clues.RepoURL != "" {
		terms = append(terms, add(clues.RepoURL, "")...)
	}
	if clues.PURL != "" {
		terms = append(terms, add(clues.PURL, "")...)
	}
	for _, p := range pd.PURLs {
		terms = append(terms, add(p, "")...)
	}
	return terms
}
