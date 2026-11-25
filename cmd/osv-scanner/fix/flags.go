package fix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/urfave/cli/v3"
	"golang.org/x/term"
)

// fixFlags returns the flags shared by the default fix action and the
// reviewable "fix plan" subcommand.
func fixFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:      "manifest",
			Aliases:   []string{"M"},
			Usage:     "manifest file to remediate vulnerabilities in",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:      "lockfile",
			Aliases:   []string{"L"},
			Usage:     "lockfile to remediate vulnerabilities in",
			TakesFile: true,
		},
		&cli.StringFlag{
			Name:  "data-source",
			Usage: "ordered, comma-separated package information sources; values can be: deps.dev, native",
			Value: "deps.dev",
			Action: func(_ context.Context, _ *cli.Command, s string) error {
				for _, source := range parseSourceNames(s, nil) {
					if source != "deps.dev" && source != "native" {
						return fmt.Errorf("unsupported data-source %q - must be one of: deps.dev, native", source)
					}
				}

				return nil
			},
		},
		&cli.StringSliceFlag{
			Name:    "source",
			Aliases: []string{"sources", "data-sources"},
			Usage:   "ordered package information source; may be repeated, and source order is fallback priority",
			Action: func(_ context.Context, _ *cli.Command, sources []string) error {
				for _, source := range parseSourceNames("", sources) {
					if source != "deps.dev" && source != "native" && !strings.HasPrefix(source, "fixture:") {
						return fmt.Errorf("unsupported source %q - must be one of: deps.dev, native", source)
					}
				}

				return nil
			},
		},
		&cli.StringFlag{
			Name:  "maven-registry",
			Usage: "URL of the default Maven registry to fetch metadata",
		},
		&cli.BoolFlag{
			Name:   "non-interactive",
			Usage:  "[DEPRECATED] run in the non-interactive mode",
			Hidden: true,
			Value:  true,
		},
		&cli.BoolFlag{
			Name:  "dry-run",
			Usage: "generate a reviewable plan and print per-file diffs without changing original files",
		},
		&cli.BoolFlag{
			Name:  "interactive",
			Usage: "run in the interactive mode",
			Action: func(_ context.Context, _ *cli.Command, b bool) error {
				if b && !term.IsTerminal(int(os.Stdin.Fd())) {
					return errors.New("interactive mode only to be run in a terminal")
				}

				return nil
			},
		},
		&cli.StringFlag{
			Name:    "format",
			Aliases: []string{"f"},
			Usage:   "sets the non-interactive output format; value can be: text, json",
			Value:   "text",
			Action: func(_ context.Context, _ *cli.Command, s string) error {
				if s == "text" || s == "json" {
					if s == "json" {
						cmdlogger.SendEverythingToStderr()
					}

					return nil
				}

				return fmt.Errorf("unsupported output format \"%s\" - must be one of: text, json", s)
			},
		},
		&cli.StringFlag{
			Category: autoModeCategory,
			Name:     "strategy",
			Usage:    "remediation approach to use; value can be: " + strings.Join(strategies, ", "),
			Action: func(_ context.Context, cmd *cli.Command, s string) error {
				switch strategy.Strategy(s) {
				case strategy.StrategyInPlace:
					if !cmd.IsSet("lockfile") {
						return fmt.Errorf("%s strategy requires lockfile", strategy.StrategyInPlace)
					}
				case strategy.Strategy("relock"): // renamed
					fallthrough
				case strategy.StrategyRelax:
					if !cmd.IsSet("manifest") {
						return fmt.Errorf("%s strategy requires manifest file", strategy.StrategyRelax)
					}
				case strategy.StrategyOverride:
					if !cmd.IsSet("manifest") {
						return fmt.Errorf("%s strategy requires manifest file", strategy.StrategyOverride)
					}
				default:
					return fmt.Errorf("unsupported strategy \"%s\" - must be one of: %s", s, strings.Join(strategies, ", "))
				}

				return nil
			},
		},
		&cli.IntFlag{
			Category: autoModeCategory,
			Name:     "apply-top",
			Usage:    "apply the top N patches",
			Value:    -1,
			Action: func(_ context.Context, _ *cli.Command, n int) error {
				if n == 0 {
					return errors.New("--apply-top must be a positive number, or -1 to apply all patches")
				}

				return nil
			},
		},
		&cli.BoolFlag{
			Category: autoModeCategory,
			Name:     "no-introduce",
			Usage:    "exclude patches that would introduce new vulnerabilities",
		},

		&cli.StringSliceFlag{
			Category:    upgradeCategory,
			Name:        "upgrade-config",
			Usage:       "the allowed package upgrades, in the format `[package-name:]level`. If package-name is omitted, level is applied to all packages. level must be one of (major, minor, patch, none).",
			DefaultText: "major",
		},
		&cli.IntFlag{
			Category: vulnCategory,
			Name:     "max-depth",
			Usage:    "maximum dependency depth of vulnerabilities to consider",
			Value:    -1,
		},
		&cli.Float64Flag{
			Category:    vulnCategory,
			Name:        "min-severity",
			Usage:       "minimum CVSS score of vulnerabilities to consider",
			Value:       0,
			DefaultText: "0.0",
		},
		&cli.StringSliceFlag{
			Category: vulnCategory,
			Name:     "vulns",
			Usage:    "explicit list of vulnerability IDs to consider",
		},
		&cli.StringSliceFlag{
			Category: vulnCategory,
			Name:     "ignore-vulns",
			Usage:    "list of vulnerability IDs to ignore",
		},
		&cli.BoolFlag{
			Category: vulnCategory,
			Name:     "ignore-dev",
			Usage:    "ignore vulnerabilities affecting only development dependencies",
		},
		&cli.BoolFlag{
			Category: vulnCategory,
			Name:     "maven-fix-management",
			Usage:    "(pom.xml) also remediate vulnerabilities in dependencyManagement packages that do not appear in the resolved dependency graph",
		},
		// Offline database flags, copied from osv-scanner scan
		&cli.BoolFlag{
			Name:    "offline-vulnerabilities",
			Aliases: []string{"offline"},
			Usage:   "checks for vulnerabilities using local databases that are already cached",
		},
		&cli.BoolFlag{
			Name:  "download-offline-databases",
			Usage: "downloads vulnerability databases for offline comparison",
		},
		&cli.StringFlag{
			Name:    "local-db-path",
			Usage:   "sets the path that local databases should be stored",
			Sources: cli.EnvVars("OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY"),
			Hidden:  true,
		}}
}
