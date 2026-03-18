package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"holmes/internal/cache"
	nameDetective "holmes/internal/detective/name"
	packageDetective "holmes/internal/detective/package"
	versionDetective "holmes/internal/detective/version"
	vulnDetective "holmes/internal/detective/vuln"
	"holmes/internal/model"
	"holmes/internal/resolver"
	"holmes/internal/service"
	"holmes/internal/service/adapters"
)

func main() {
	store, err := cache.NewSQLiteStore("holmes_cache.db")
	if err != nil {
		log.Fatalf("failed to init cache: %v", err)
	}
	cached := service.NewCachedClient(&http.Client{Timeout: 60 * time.Second}, store, service.CacheConfig{
		DefaultTTL: 24 * time.Hour,
		ServiceTTL: map[string]time.Duration{},
	}, 3)

	npmAdapter := adapters.NewNpmAdapter(cached)
	pypiAdapter := adapters.NewPyPIAdapter(cached)
	goAdapter := adapters.NewGoAdapter(cached)
	ecosystemsAdapter := adapters.NewEcosystemsAdapter(cached)
	osvAdapter := adapters.NewOSVAdapter(cached)

	res := resolver.New(
		nameDetective.New(npmAdapter, pypiAdapter, goAdapter),
		packageDetective.New(ecosystemsAdapter, store),
		vulnDetective.New(osvAdapter, store),
		versionDetective.New(),
	)

	http.HandleFunc("/resolve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var req model.ResolveRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid json", http.StatusBadRequest)
			return
		}
		if !validInput(req) {
			http.Error(w, "provide name+ecosystem, repository_url, or purl", http.StatusBadRequest)
			return
		}
		report := res.Resolve(r.Context(), req)
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(report); err != nil {
			http.Error(w, "failed to encode response", http.StatusInternalServerError)
			return
		}
	})

	log.Println("holmes server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}

func validInput(req model.ResolveRequest) bool {
	if req.Name != "" && req.Ecosystem != "" {
		return true
	}
	if req.RepositoryURL != "" || req.PURL != "" {
		return true
	}
	return false
}
