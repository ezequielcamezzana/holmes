package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"holmes/internal/model"
)

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func cmdResolve(res Resolver, args []string) {
	fs := flag.NewFlagSet("resolve", flag.ExitOnError)
	name    := fs.String("name", "", "package name")
	eco     := fs.String("eco", "", "ecosystem (npm, pypi, go)")
	purl    := fs.String("purl", "", "package URL (pkg:npm/axios or pkg:npm/axios@1.2.2)")
	url     := fs.String("url", "", "repository URL")
	version := fs.String("version", "", "version to check for vulnerability assessment")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: holmes resolve [flags]\n\nFlags:")
		fs.PrintDefaults()
	}
	_ = fs.Parse(args)

	req := model.ResolveRequest{
		Name:          *name,
		Ecosystem:     *eco,
		PURL:          *purl,
		RepositoryURL: *url,
		Version:       *version,
	}
	if req.Name == "" && req.PURL == "" && req.RepositoryURL == "" {
		fs.Usage()
		os.Exit(1)
	}

	label := resolveLabel(req)

	// Animated spinner while waiting for the server.
	stop := make(chan struct{})
	go func() {
		i := 0
		for {
			select {
			case <-stop:
				return
			case <-time.After(80 * time.Millisecond):
				frame := spinColor.Render(spinFrames[i%len(spinFrames)])
				fmt.Fprintf(os.Stderr, "\r%s %s", frame, label)
				i++
			}
		}
	}()

	report, err := res.Resolve(context.Background(), req)
	close(stop)
	fmt.Fprintf(os.Stderr, "\r\033[K") // clear spinner line

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	printReport(report)
}

func resolveLabel(req model.ResolveRequest) string {
	if req.PURL != "" {
		return req.PURL
	}
	if req.Name != "" && req.Ecosystem != "" {
		if req.Version != "" {
			return req.Name + "@" + req.Version + " [" + req.Ecosystem + "]"
		}
		return req.Name + " [" + req.Ecosystem + "]"
	}
	if req.RepositoryURL != "" {
		return req.RepositoryURL
	}
	return "package"
}
