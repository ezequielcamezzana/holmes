package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"holmes/internal/cache"
)

type CacheConfig struct {
	DefaultTTL time.Duration
	ServiceTTL map[string]time.Duration
}

type CachedClient struct {
	httpClient *http.Client
	cache      cache.Store
	cacheCfg   CacheConfig
	schema     int
}

func NewCachedClient(httpClient *http.Client, store cache.Store, cfg CacheConfig, schemaVersion int) *CachedClient {
	return &CachedClient{httpClient: httpClient, cache: store, cacheCfg: cfg, schema: schemaVersion}
}

func (c *CachedClient) FetchJSON(ctx context.Context, serviceName string, req Request, out any) error {
	if c.cache != nil && req.Key != "" {
		entry, err := c.cache.Get(ctx, req.Key)
		if err == nil && entry != nil && entry.SchemaVersion == c.schema {
			return json.Unmarshal(entry.Value, out)
		}
	}

	hreq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return err
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	if req.Method == http.MethodPost && hreq.Header.Get("Content-Type") == "" {
		hreq.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(hreq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	log.Printf("[%d][%s]", resp.StatusCode, req.URL)
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, out); err != nil {
		return err
	}

	if c.cache != nil && req.Key != "" && (req.CacheFilter == nil || req.CacheFilter(body)) {
		ttl := c.cacheCfg.DefaultTTL
		if t, ok := c.cacheCfg.ServiceTTL[serviceName]; ok {
			ttl = t
		}
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		cachedBytes, _ := json.Marshal(out)
		_ = c.cache.Set(ctx, req.Key, cachedBytes, ttl, c.schema)
	}
	return nil
}

func (c *CachedClient) FetchBytes(ctx context.Context, req Request) ([]byte, error) {
	hreq, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(req.Body))
	if err != nil {
		return nil, err
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	resp, err := c.httpClient.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	log.Printf("[%d][%s]", resp.StatusCode, req.URL)
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("http %d: %s", resp.StatusCode, string(body))
	}
	return io.ReadAll(resp.Body)
}
