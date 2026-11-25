package fixplan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"deps.dev/util/resolve"
)

type unavailableClient struct{}

func (unavailableClient) Version(context.Context, resolve.VersionKey) (resolve.Version, error) {
	return resolve.Version{}, fmt.Errorf("%w: test source down", ErrSourceUnavailable)
}
func (unavailableClient) Versions(context.Context, resolve.PackageKey) ([]resolve.Version, error) {
	return nil, fmt.Errorf("%w: test source down", ErrSourceUnavailable)
}
func (unavailableClient) Requirements(context.Context, resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	return nil, fmt.Errorf("%w: test source down", ErrSourceUnavailable)
}
func (unavailableClient) MatchingVersions(context.Context, resolve.VersionKey) ([]resolve.Version, error) {
	return nil, fmt.Errorf("%w: test source down", ErrSourceUnavailable)
}

func npmPackage(name string) resolve.PackageKey {
	return resolve.PackageKey{System: resolve.NPM, Name: name}
}

func npmVersion(name, version string) resolve.Version {
	return resolve.Version{
		PackageKey:  npmPackage(name),
		VersionType: resolve.Concrete,
		Version:     version}
}

func clientWithVersions(name string, versions ...string) *resolve.LocalClient {
	c := resolve.NewLocalClient()
	for _, v := range versions {
		c.AddVersion(npmVersion(name, v), nil)
	}

	return c
}

func TestRouterFallbackOnMissingPackageAndVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	pk := npmPackage("demo")
	vk := resolve.VersionKey{PackageKey: pk, VersionType: resolve.Concrete, Version: "1.2.3"}

	t.Run("version not found falls back", func(t *testing.T) {
		t.Parallel()
		r, err := NewRouter([]ResolveSource{
			{Name: "high", Client: resolve.NewLocalClient()},
			{Name: "low", Client: clientWithVersions("demo", "1.2.3")},
		})
		if err != nil {
			t.Fatal(err)
		}
		v, err := r.Version(ctx, vk)
		if err != nil {
			t.Fatalf("expected fallback success, got %v", err)
		}
		if v.Version != "1.2.3" {
			t.Fatalf("Version = %q", v.Version)
		}
		deps := r.Provenance()
		if len(deps) != 1 || deps[0].SelectedSource != "low" {
			t.Fatalf("provenance = %+v", deps)
		}
		if deps[0].SelectionReason != "fallback_after_not_found" {
			t.Fatalf("reason = %q", deps[0].SelectionReason)
		}
	})

	t.Run("package not found in Versions falls back", func(t *testing.T) {
		t.Parallel()
		r, err := NewRouter([]ResolveSource{
			{Name: "high", Client: resolve.NewLocalClient()},
			{Name: "low", Client: clientWithVersions("demo", "1.2.3", "1.3.0")},
		})
		if err != nil {
			t.Fatal(err)
		}
		vs, err := r.Versions(ctx, pk)
		if err != nil {
			t.Fatal(err)
		}
		if len(vs) != 2 {
			t.Fatalf("len(Versions) = %d", len(vs))
		}
		var selected string
		for _, d := range r.Provenance() {
			if d.Key == pk.String() {
				selected = d.SelectedSource
			}
		}
		if selected != "low" {
			t.Fatalf("selected = %q, reports=%+v", selected, r.Provenance())
		}
	})
}

func TestRouterFallbackOnUnavailableSource(t *testing.T) {
	t.Parallel()
	r, err := NewRouter([]ResolveSource{
		{Name: "high", Client: unavailableClient{}},
		{Name: "low", Client: clientWithVersions("demo", "2.0.0")},
	})
	if err != nil {
		t.Fatal(err)
	}
	vs, err := r.Versions(context.Background(), npmPackage("demo"))
	if err != nil {
		t.Fatalf("expected available fallback, got %v", err)
	}
	if len(vs) != 1 || vs[0].Version != "2.0.0" {
		t.Fatalf("versions = %+v", vs)
	}
	var report SourceReport
	for _, s := range r.Reports() {
		if s.Name == "high" {
			report = s
		}
	}
	if report.Status != "unavailable" || report.Code != CodeSourceUnavailable {
		t.Fatalf("high report = %+v", report)
	}
}

func TestRouterAllSourcesFail(t *testing.T) {
	t.Parallel()

	t.Run("all unavailable", func(t *testing.T) {
		t.Parallel()
		r, _ := NewRouter([]ResolveSource{
			{Name: "a", Client: unavailableClient{}},
			{Name: "b", Client: unavailableClient{}},
		})
		_, err := r.Versions(context.Background(), npmPackage("demo"))
		var sel *SourceSelectionError
		if !errors.As(err, &sel) {
			t.Fatalf("error type = %T %v", err, err)
		}
		if sel.Code != CodeAllSourcesUnavailable {
			t.Fatalf("code = %q", sel.Code)
		}
	})

	t.Run("all explicitly missing", func(t *testing.T) {
		t.Parallel()
		r, _ := NewRouter([]ResolveSource{
			{Name: "a", Client: resolve.NewLocalClient()},
			{Name: "b", Client: resolve.NewLocalClient()},
		})
		_, err := r.Versions(context.Background(), npmPackage("demo"))
		var sel *SourceSelectionError
		if !errors.As(err, &sel) {
			t.Fatalf("error type = %T %v", err, err)
		}
		if sel.Code != CodeNoAvailableVersion {
			t.Fatalf("code = %q", sel.Code)
		}
	})
}

func TestRouterPinsOneSourcePerDependency(t *testing.T) {
	t.Parallel()
	pk := npmPackage("pinned")
	high := clientWithVersions("pinned", "1.0.0")
	low := clientWithVersions("pinned", "1.0.0", "9.9.9")
	r, err := NewRouter([]ResolveSource{{Name: "high", Client: high}, {Name: "low", Client: low}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := r.Versions(ctx, pk); err != nil {
		t.Fatal(err)
	}
	reqs, err := r.Requirements(ctx, resolve.VersionKey{PackageKey: pk, VersionType: resolve.Concrete, Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 0 {
		t.Fatalf("requirements = %+v", reqs)
	}
	deps := r.Provenance()
	if len(deps) != 1 || deps[0].SelectedSource != "high" {
		t.Fatalf("dependency was not pinned to high: %+v", deps)
	}
	for _, a := range deps[0].Attempts {
		if a.Source == "low" {
			t.Fatalf("low source was used after high provided graph: %+v", deps[0])
		}
	}
}

func TestRedactTextRemovesCredentials(t *testing.T) {
	t.Parallel()
	//nolint:gosec // G101 flags deliberately fake credential fixtures.
	in := "fetch https://user:supersecret@source.example/v1?token=abc123&ok=1 failed: Authorization: Bearer zzz-secret and X-Api-Key: key-secret"
	got := RedactText(in)
	for _, secret := range []string{"supersecret", "abc123", "zzz-secret", "key-secret"} {
		if strings.Contains(got, secret) {
			t.Fatalf("redacted output still contains %q:\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "<redacted>") {
		t.Fatalf("expected redaction marker: %s", got)
	}
}
