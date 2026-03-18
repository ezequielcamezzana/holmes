package adapters

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"holmes/internal/service"
)

type PyPIAdapter struct {
	client *service.CachedClient
}

func NewPyPIAdapter(client *service.CachedClient) *PyPIAdapter {
	return &PyPIAdapter{client: client}
}

type pypiRegistryResponse struct {
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
}

func (a *PyPIAdapter) ResolveName(ctx context.Context, name string) (string, error) {
	var res pypiRegistryResponse
	err := a.client.FetchJSON(ctx, "pypi", service.Request{
		Key:    fmt.Sprintf("pypi:%s:pypi:registry", name),
		URL:    "https://pypi.org/pypi/" + url.PathEscape(name) + "/json",
		Method: http.MethodGet,
	}, &res)
	if err != nil {
		return "", err
	}
	if res.Info.Name == "" {
		return "", fmt.Errorf("empty pypi package name in response")
	}
	return res.Info.Name, nil
}
