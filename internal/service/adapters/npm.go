package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"holmes/internal/service"
)

type NpmAdapter struct {
	client *service.CachedClient
}

func NewNpmAdapter(client *service.CachedClient) *NpmAdapter {
	return &NpmAdapter{client: client}
}

type npmRegistryResponse struct {
	Name string `json:"name"`
}

func (a *NpmAdapter) ResolveName(ctx context.Context, name string) (string, error) {
	var res npmRegistryResponse
	err := a.client.FetchJSON(ctx, "npm", service.Request{
		Key:    fmt.Sprintf("npm:%s:npmjs:registry", name),
		URL:    "https://registry.npmjs.org/" + url.PathEscape(name),
		Method: http.MethodGet,
	}, &res)
	if err != nil {
		return "", err
	}
	if res.Name == "" {
		return "", fmt.Errorf("empty npm package name in response")
	}
	return res.Name, nil
}
