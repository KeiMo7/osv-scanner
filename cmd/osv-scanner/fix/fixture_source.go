package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scanner/v2/internal/fixplan"
)

type fixtureCatalogFile struct {
	Unavailable bool             `json:"unavailable"`
	Packages    []fixturePackage `json:"packages"`
}

type fixturePackage struct {
	System       string                       `json:"system"`
	Name         string                       `json:"name"`
	Versions     []string                     `json:"versions"`
	Requirements []fixtureVersionRequirements `json:"requirements"`
}

type fixtureVersionRequirements struct {
	Version      string               `json:"version"`
	Dependencies []fixtureRequirement `json:"dependencies"`
}

type fixtureRequirement struct {
	System  string `json:"system"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type fixtureResolveClient struct {
	path        string
	unavailable bool
	local       *resolve.LocalClient
}

func newFixtureResolveClient(path string) (resolve.Client, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read source fixture: %w", err)
	}
	var catalog fixtureCatalogFile
	if err := json.Unmarshal(b, &catalog); err != nil {
		return nil, fmt.Errorf("parse source fixture: %w", err)
	}

	c := &fixtureResolveClient{path: path, unavailable: catalog.Unavailable, local: resolve.NewLocalClient()}
	for _, pkg := range catalog.Packages {
		sys := parseFixtureSystem(pkg.System)
		pk := resolve.PackageKey{System: sys, Name: pkg.Name}
		reqsByVersion := map[string][]fixtureRequirement{}
		for _, vr := range pkg.Requirements {
			reqsByVersion[vr.Version] = vr.Dependencies
		}
		for _, version := range pkg.Versions {
			vk := resolve.VersionKey{PackageKey: pk, VersionType: resolve.Concrete, Version: version}
			var deps []resolve.RequirementVersion
			for _, d := range reqsByVersion[version] {
				deps = append(deps, resolve.RequirementVersion{
					System: parseFixtureSystem(d.System), Name: d.Name,
					VersionType: resolve.Requirement,
					Version:     d.Version})
			}
			c.local.AddVersion(resolve.Version{VersionKey: vk}, deps)
		}
	}

	return c, nil
}

func parseFixtureSystem(s string) resolve.System {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "npm":
		return resolve.NPM
	case "maven":
		return resolve.Maven
	case "pypi":
		return resolve.PyPI
	default:
		return resolve.UnknownSystem
	}
}

func (c *fixtureResolveClient) maybeUnavailable() error {
	if c.unavailable {
		return fmt.Errorf("%w: fixture marked unavailable", fixplan.ErrSourceUnavailable)
	}

	return nil
}

func (c *fixtureResolveClient) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	if err := c.maybeUnavailable(); err != nil {
		return resolve.Version{}, err
	}

	return c.local.Version(ctx, vk)
}

func (c *fixtureResolveClient) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	if err := c.maybeUnavailable(); err != nil {
		return nil, err
	}

	return c.local.Versions(ctx, pk)
}

func (c *fixtureResolveClient) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	if err := c.maybeUnavailable(); err != nil {
		return nil, err
	}

	return c.local.Requirements(ctx, vk)
}

func (c *fixtureResolveClient) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	if err := c.maybeUnavailable(); err != nil {
		return nil, err
	}

	return c.local.MatchingVersions(ctx, vk)
}

var _ resolve.Client = (*fixtureResolveClient)(nil)
