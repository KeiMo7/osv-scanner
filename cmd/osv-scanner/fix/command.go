// Package fix implements the `fix` command for osv-scanner.
// It scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them.
package fix

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"

	"charm.land/glamour/v2"
	"charm.land/glamour/v2/ansi"
	"charm.land/glamour/v2/styles"
	"charm.land/lipgloss/v2"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/urfave/cli/v3"
)

var strategies = []string{string(strategy.StrategyInPlace), string(strategy.StrategyRelax), string(strategy.StrategyOverride)}

const (
	vulnCategory     = "Vulnerability Selection Options:"
	upgradeCategory  = "Dependency Upgrade Options:"
	autoModeCategory = "non-interactive options:" // intentionally lowercase to force it to sort after the other categories
	depsdevAPI       = "api.deps.dev:443"
)

func Command(stdout, _ io.Writer, clientFactories config.ClientFactories) *cli.Command {
	return &cli.Command{
		Name:        "fix",
		Usage:       "scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them",
		Description: "scans a manifest and/or lockfile for vulnerabilities and suggests changes for remediating them. This feature can be risky when run on untrusted projects. Please ensure you trust the source code and artifacts before proceeding.",
		Flags: append(fixFlags(), &cli.StringFlag{
			Name:    "plan-out",
			Aliases: []string{"p", "plan"},
			Usage:   "with --dry-run, write the reviewable JSON plan to this path",
		}),
		Commands: []*cli.Command{
			planCommand(stdout, clientFactories),
			applyPlanCommand(stdout),
			comparePlansCommand(stdout),
			recoverCommand(stdout),
			sourceResolveCommand(stdout, clientFactories),
		},
		Action: func(ctx context.Context, cmd *cli.Command) error {
			return redactError(action(ctx, cmd, stdout, clientFactories))
		},
	}
}

func action(ctx context.Context, cmd *cli.Command, stdout io.Writer, clientFactories config.ClientFactories) error {
	cmdlogger.Warnf("Guided remediation (the fix command) can be risky when run on untrusted projects. It may trigger the package manager to execute scripts or follow external registries specified in the project. Please ensure you trust the source code and artifacts before proceeding.")
	if !cmd.IsSet("manifest") && !cmd.IsSet("lockfile") {
		return errors.New("manifest or lockfile is required")
	}
	if cmd.Bool("dry-run") {
		return executePlan(ctx, cmd, stdout, clientFactories)
	}

	opts := buildFixOptions(cmd)

	ua := userAgent()
	cf, cleanup := setupFactories(clientFactories, ua)
	defer cleanup()

	// MavenClient is required for Maven projects
	mc, err := datasource.NewMavenRegistryAPIClient(
		ctx,
		datasource.MavenRegistry{
			URL:             cmd.String("maven-registry"),
			ReleasesEnabled: true,
		},
		"",
		false,
		false,
		cf.HTTPClient(),
		nil,
	)
	if err != nil {
		return err
	}
	opts.MavenClient = mc

	workDir := filepath.Dir(firstNonEmpty(opts.Manifest, opts.Lockfile))
	sourceSetup, err := configureResolveClient(cmd, cf, workDir, cmd.String("maven-registry"))
	if err != nil {
		return err
	}
	opts.ResolveClient = sourceSetup.client

	opts.VulnEnricher, err = buildVulnEnricher(cmd, cf, ua)
	if err != nil {
		return err
	}

	if cmd.Bool("interactive") {
		return guidedremediation.FixVulnsInteractive(opts, GlamourRenderer{})
	}

	res, err := guidedremediation.FixVulns(opts)
	if err != nil {
		return err
	}

	redactResultSecrets(&res)

	outputJSON := cmd.String("format") == "json"

	return printResult(res, outputJSON, stdout)
}

type GlamourRenderer struct{}

func (GlamourRenderer) Render(details string, width int) (string, error) {
	var style ansi.StyleConfig
	if lipgloss.HasDarkBackground(os.Stdin, os.Stdout) {
		style = styles.DarkStyleConfig
	} else {
		style = styles.LightStyleConfig
	}
	*style.Document.Margin = 0
	style.Document.BlockPrefix = ""

	r, err := glamour.NewTermRenderer(
		glamour.WithStyles(style),
		glamour.WithWordWrap(width),
	)
	if err != nil {
		return "", err
	}

	return r.Render(details)
}
