package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"holmes/internal/model"
)

// Resolver is a thin interface so commands don't depend on the concrete resolver
// or HTTP transport directly.
type Resolver interface {
	Resolve(ctx context.Context, req model.ResolveRequest) (model.CaseReport, error)
}

// httpResolver calls the holmes server's POST /resolve endpoint.
type httpResolver struct {
	base   string
	client *http.Client
}

func (r *httpResolver) Resolve(ctx context.Context, req model.ResolveRequest) (model.CaseReport, error) {
	buf, err := json.Marshal(req)
	if err != nil {
		return model.CaseReport{}, err
	}
	hreq, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(r.base, "/")+"/resolve", bytes.NewReader(buf))
	if err != nil {
		return model.CaseReport{}, err
	}
	hreq.Header.Set("Content-Type", "application/json")

	resp, err := r.client.Do(hreq)
	if err != nil {
		return model.CaseReport{}, fmt.Errorf("server unreachable (%s): %w", r.base, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var raw map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&raw)
		return model.CaseReport{}, fmt.Errorf("http %d: %v", resp.StatusCode, raw)
	}

	var report model.CaseReport
	if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
		return model.CaseReport{}, fmt.Errorf("decoding response: %w", err)
	}
	return report, nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	res := setup()

	switch os.Args[1] {
	case "resolve":
		cmdResolve(res, os.Args[2:])
	case "scan":
		cmdScan(res, os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func setup() Resolver {
	base := strings.TrimSpace(os.Getenv("HOLMES_API_BASE"))
	if base == "" {
		base = "http://localhost:8080"
	}
	return &httpResolver{
		base:   base,
		client: &http.Client{Timeout: 120 * time.Second},
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `Usage: holmes <command> [flags]

Commands:
  resolve   Investigate a single package
  scan      Scan a CycloneDX SBOM

Run 'holmes <command> --help' for details.

Set HOLMES_API_BASE to override the server address (default: http://localhost:8080).`)
}
