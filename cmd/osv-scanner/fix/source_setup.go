package fix

import (
	"fmt"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func parseSourceNames(csvValue string, repeated []string) []string {
	var raw []string
	if csvValue != "" {
		raw = append(raw, strings.Split(csvValue, ",")...)
	}
	for _, v := range repeated {
		raw = append(raw, strings.Split(v, ",")...)
	}

	var out []string
	seen := map[string]struct{}{}
	for _, item := range raw {
		name := strings.TrimSpace(item)
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return []string{"deps.dev"}
	}

	return out
}

func configuredSourceNames(cmd *cli.Command) []string {
	// The repeated flag takes precedence when explicitly provided. This keeps
	// the historical --data-source value and its meaning intact.
	if cmd.IsSet("source") {
		return parseSourceNames("", cmd.StringSlice("source"))
	}

	return parseSourceNames(cmd.String("data-source"), nil)
}

type resolveSourceSetup struct {
	client resolve.Client
	router *fixplan.Router
}

// configureResolveClient builds sources in CLI order. With one source the
// source client is returned directly to preserve the historical code path and
// output exactly. With multiple sources it returns a pinned priority router.
func configureResolveClient(
	cmd *cli.Command,
	cf config.ClientFactories,
	workDir string,
	mavenRegistry string,
) (*resolveSourceSetup, error) {
	names := configuredSourceNames(cmd)
	sources := make([]fixplan.ResolveSource, 0, len(names))
	seenLabels := map[string]int{}
	for i, name := range names {
		client, err := newResolveSourceClient(name, cf, workDir, mavenRegistry)
		if err != nil {
			return nil, fmt.Errorf("data source %d (%q) is unavailable: %w", i+1, redactSourceName(name), err)
		}
		label := sourceLabel(name, i)
		if count := seenLabels[label]; count > 0 {
			label = fmt.Sprintf("%s-%d", label, count+1)
		}
		seenLabels[sourceLabel(name, i)]++
		sources = append(sources, fixplan.ResolveSource{Name: label, Client: client})
	}

	if len(sources) == 1 {
		return &resolveSourceSetup{client: sources[0].Client}, nil
	}
	router, err := fixplan.NewRouter(sources)
	if err != nil {
		return nil, err
	}

	return &resolveSourceSetup{client: router, router: router}, nil
}

func newResolveSourceClient(
	name string,
	cf config.ClientFactories,
	workDir string,
	mavenRegistry string,
) (resolve.Client, error) {
	switch {
	case name == "deps.dev":
		conn, err := cf.GRPCClientConn(depsdevAPI)
		if err != nil {
			return nil, err
		}

		return resolution.NewDepsDevClientWithConn(conn), nil
	case name == "native":
		return resolution.NewCombinedNativeClient(resolution.CombinedNativeClientOptions{
			HTTPClient:        cf.HTTPClient(),
			DisableGoogleAuth: true,
			ProjectDir:        workDir,
			MavenRegistry:     mavenRegistry,
		})
	case strings.HasPrefix(name, "fixture:"):
		return newFixtureResolveClient(strings.TrimPrefix(name, "fixture:"))
	default:
		return nil, fmt.Errorf("unsupported data source %q", redactSourceName(name))
	}
}

func sourceLabel(name string, index int) string {
	if after, ok := strings.CutPrefix(name, "fixture:"); ok {
		path := after

		return "fixture:" + filepath.Base(path)
	}
	_ = index

	return name
}

func redactSourceName(name string) string {
	return fixplan.RedactText(name)
}
