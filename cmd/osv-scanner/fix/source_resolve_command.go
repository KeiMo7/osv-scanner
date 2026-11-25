package fix

import (
	"context"
	"errors"
	"fmt"
	"io"

	"deps.dev/util/resolve"
	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func sourceResolveCommand(stdout io.Writer, clientFactories scalibrconfig.ClientFactories) *cli.Command {
	return &cli.Command{
		Name:   "resolve-source",
		Usage:  "resolve one package through the ordered source chain (test/diagnostic command)",
		Hidden: true,
		Flags: []cli.Flag{
			&cli.StringSliceFlag{Name: "source", Aliases: []string{"sources", "data-sources"}, Usage: "ordered sources"},
			&cli.StringFlag{Name: "system", Usage: "npm, maven, or pypi", Value: "npm"},
			&cli.StringFlag{Name: "package", Usage: "package name"},
			&cli.StringFlag{Name: "version", Usage: "exact version to look up"},
			&cli.StringFlag{Name: "constraint", Usage: "requirement constraint to match"},
			&cli.StringFlag{Name: "format", Value: "text", Usage: "text or json"},
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			if cmd.String("package") == "" {
				return errors.New("--package is required")
			}
			names := parseSourceNames("", cmd.StringSlice("source"))
			ua := userAgent()
			cf, cleanup := setupFactories(clientFactories, ua)
			defer cleanup()

			var sources []fixplan.ResolveSource
			for i, name := range names {
				c, err := newResolveSourceClient(name, cf, ".", "")
				if err != nil {
					return err
				}
				sources = append(sources, fixplan.ResolveSource{Name: sourceLabel(name, i), Client: c})
			}
			router, err := fixplan.NewRouter(sources)
			if err != nil {
				return err
			}
			pk := resolve.PackageKey{System: parseFixtureSystem(cmd.String("system")), Name: cmd.String("package")}

			result := map[string]any{"package": pk.String(), "sources": names}
			switch {
			case cmd.String("version") != "":
				vk := resolve.VersionKey{PackageKey: pk, VersionType: resolve.Concrete, Version: cmd.String("version")}
				v, err := router.Version(ctx, vk)
				if err != nil {
					return sourceResolveError(cmd, stdout, router, err)
				}
				result["version"] = v.Version
			case cmd.String("constraint") != "":
				vk := resolve.VersionKey{PackageKey: pk, VersionType: resolve.Requirement, Version: cmd.String("constraint")}
				vs, err := router.MatchingVersions(ctx, vk)
				if err != nil {
					return sourceResolveError(cmd, stdout, router, err)
				}
				result["matching_versions"] = versionStrings(vs)
			default:
				vs, err := router.Versions(ctx, pk)
				if err != nil {
					return sourceResolveError(cmd, stdout, router, err)
				}
				result["versions"] = versionStrings(vs)
			}
			result["selected"] = router.Provenance()
			if cmd.String("format") == "json" {
				return writeJSON(stdout, result)
			}
			fmt.Fprintf(stdout, "PACKAGE: %s\n", pk.String())
			for _, p := range router.Provenance() {
				fmt.Fprintf(stdout, "SELECTED-SOURCE: %s -> %s (%s)\n", p.Name, p.SelectedSource, p.SelectionReason)
			}

			return nil
		},
	}
}

func versionStrings(vs []resolve.Version) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Version)
	}

	return out
}

func sourceResolveError(cmd *cli.Command, stdout io.Writer, router *fixplan.Router, err error) error {
	if cmd.String("format") == "json" {
		_ = writeJSON(stdout, map[string]any{
			"ok":       false,
			"error":    safeError(err),
			"sources":  router.Reports(),
			"selected": router.Provenance(),
		})
	}

	return redactError(err)
}
