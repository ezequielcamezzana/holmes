package name

import (
	"context"
	"net/http"
	"strings"

	"holmes/internal/model"
	"holmes/internal/service/adapters"
)

type Detective struct {
	npm  *adapters.NpmAdapter
	pypi *adapters.PyPIAdapter
	goa  *adapters.GoAdapter
}

func New(npm *adapters.NpmAdapter, pypi *adapters.PyPIAdapter, goa *adapters.GoAdapter) *Detective {
	return &Detective{npm: npm, pypi: pypi, goa: goa}
}

func (d *Detective) Investigate(ctx context.Context, clues *model.Clues) (model.Investigation, error) {
	inv := model.Investigation{Detective: "name", Status: model.StatusSuccess}
	if clues.RepoURL != "" || clues.PURL != "" {
		inv.Status = model.StatusSkipped
		return inv, nil
	}
	if clues.RawName == "" || clues.Ecosystem == "" {
		inv.Status = model.StatusSkipped
		inv.Error = "missing name or ecosystem"
		return inv, nil
	}
	eco := strings.ToLower(clues.Ecosystem)
	var (
		resolved string
		err      error
	)
	switch eco {
	case "npm":
		resolved, err = d.npm.ResolveName(ctx, clues.RawName)
	case "pypi":
		resolved, err = d.pypi.ResolveName(ctx, clues.RawName)
	case "go", "golang":
		resolved, err = d.goa.ResolveName(ctx, clues.RawName)
	default:
		inv.Status = model.StatusSkipped
		inv.Error = "unsupported ecosystem"
		return inv, nil
	}
	if err != nil {
		if strings.HasPrefix(err.Error(), "http 404") || strings.Contains(err.Error(), http.StatusText(http.StatusNotFound)) {
			inv.Status = model.StatusSkipped
			inv.Error = "package not found in registry"
			return inv, nil
		}
		inv.Status = model.StatusFailed
		inv.Error = err.Error()
		return inv, nil
	}
	clues.ResolvedName = resolved
	inv.Result = map[string]string{"resolved_name": resolved}
	return inv, nil
}
