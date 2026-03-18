package service

import "context"

type Request struct {
	Key         string
	URL         string
	Method      string
	Body        []byte
	Headers     map[string]string
	CacheFilter func([]byte) bool // if non-nil, only cache when this returns true
}

type Service[T any] interface {
	Fetch(ctx context.Context, req Request) (T, error)
}
