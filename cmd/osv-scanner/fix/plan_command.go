package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/guidedremediation"
	"github.com/google/osv-scalibr/guidedremediation/result"
	scalibrconfig "github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func planCommand(stdout io.Writer, clientFactories scalibrconfig.ClientFactories) *cli.Command {
	flags := append(fixFlags(),
		&cli.StringFlag{
			Name:    "plan-out",
			Aliases: []string{"p", "plan"},
			Usage:   "write the reviewable JSON plan to this path",
		},
		&cli.StringFlag{
			Name:  "state-dir",
			Usage: "directory used for apply locks and crash-recovery journals",
		},
	)

	return &cli.Command{
		Name:        "plan",
		Usage:       "generate a reviewable, replayable fix plan without changing original files",
		Description: "Runs guided remediation in a temporary sandbox and records complete target file contents and hashes. Original manifest and lockfile paths are never written, renamed, or replaced.",
		Flags:       flags,
		Action: func(ctx context.Context, cmd *cli.Command) error {
			cmdlogger.Warnf("Guided remediation (the fix command) can be risky when run on untrusted projects. It may trigger the package manager to execute scripts or follow external registries specified in the project. Please ensure you trust the source code and artifacts before proceeding.")

			return redactError(executePlan(ctx, cmd, stdout, clientFactories))
		},
	}
}

type originalTarget struct {
	original string
	abs      string
	display  string
	sandbox  string
	before   []byte
	mode     os.FileMode
}

func executePlan(ctx context.Context, cmd *cli.Command, stdout io.Writer, clientFactories scalibrconfig.ClientFactories) error {
	plan, res, _, err := generatePlan(ctx, cmd, clientFactories)
	if err != nil {
		return err
	}

	if out := cmd.String("plan-out"); out != "" {
		if err := fixplan.WritePlanFile(out, plan); err != nil {
			return fmt.Errorf("cannot write plan file: %w", err)
		}
		cmdlogger.Infof("PLAN-WRITTEN: %s (%s)", out, plan.ID)
	}

	if cmd.String("format") == "json" {
		return outputPlanJSON(stdout, res, plan)
	}

	if err := outputText(stdout, res); err != nil {
		return err
	}
	if len(plan.Files) == 0 {
		cmdlogger.Infof("PLAN-ID: %s (no file changes)", plan.ID)

		return nil
	}
	cmdlogger.Infof("PLAN-ID: %s", plan.ID)
	cmdlogger.Infof("Review the diff below; apply with: osv-scanner fix apply --plan <plan.json>")
	if err := plan.WriteTextDiffs(stdout); err != nil {
		return err
	}

	return nil
}

func generatePlan(
	ctx context.Context,
	cmd *cli.Command,
	clientFactories scalibrconfig.ClientFactories,
) (*fixplan.Plan, result.Result, *resolveSourceSetup, error) {
	if !cmd.IsSet("manifest") && !cmd.IsSet("lockfile") {
		return nil, result.Result{}, nil, errors.New("manifest or lockfile is required")
	}

	opts := buildFixOptions(cmd)
	ua := userAgent()
	cf, cleanup := setupFactories(clientFactories, ua)
	defer cleanup()

	mc, err := datasource.NewMavenRegistryAPIClient(
		ctx,
		datasource.MavenRegistry{URL: cmd.String("maven-registry"), ReleasesEnabled: true},
		"", false, false, cf.HTTPClient(), nil,
	)
	if err != nil {
		return nil, result.Result{}, nil, err
	}
	opts.MavenClient = mc

	workDir := filepath.Dir(firstNonEmpty(opts.Manifest, opts.Lockfile))
	sources, err := configureResolveClient(cmd, cf, workDir, cmd.String("maven-registry"))
	if err != nil {
		return nil, result.Result{}, nil, err
	}
	opts.ResolveClient = sources.client

	opts.VulnEnricher, err = buildVulnEnricher(cmd, cf, ua)
	if err != nil {
		return nil, result.Result{}, nil, err
	}

	targets, err := snapshotPlanTargets(opts.Manifest, opts.Lockfile)
	if err != nil {
		return nil, result.Result{}, nil, err
	}

	sandboxDir, err := os.MkdirTemp("", "osv-scanner-fix-plan-*")
	if err != nil {
		return nil, result.Result{}, nil, fmt.Errorf("cannot create temporary plan sandbox: %w", err)
	}
	defer os.RemoveAll(sandboxDir)

	for i := range targets {
		t := &targets[i]
		t.sandbox = filepath.Join(sandboxDir, filepath.Base(t.original))
		if _, err := os.Stat(t.sandbox); err == nil {
			return nil, result.Result{}, nil, fmt.Errorf("two targets share basename %q; pass them from separate invocations", filepath.Base(t.original))
		}
		if err := os.WriteFile(t.sandbox, t.before, t.mode); err != nil {
			return nil, result.Result{}, nil, fmt.Errorf("cannot stage plan sandbox: %w", err)
		}
	}
	if opts.Manifest != "" {
		opts.Manifest = sandboxPathFor(opts.Manifest, targets)
	}
	if opts.Lockfile != "" {
		opts.Lockfile = sandboxPathFor(opts.Lockfile, targets)
	}
	opts.ProjectRoot = sandboxDir

	res, fixErr := guidedremediation.FixVulns(opts)
	if fixErr != nil {
		if selErr, ok := errors.AsType[*fixplan.SourceSelectionError](fixErr); ok {
			return nil, result.Result{}, sources, selErr
		}
		if sources.router != nil && allSourcesUnavailable(sources.router.Reports()) {
			return nil, result.Result{}, sources, &fixplan.SourceSelectionError{Code: fixplan.CodeAllSourcesUnavailable}
		}

		return nil, result.Result{}, sources, fixErr
	}
	if sources.router != nil && allSourcesUnavailable(sources.router.Reports()) {
		return nil, result.Result{}, sources, &fixplan.SourceSelectionError{Code: fixplan.CodeAllSourcesUnavailable}
	}

	redactResultSecrets(&res)
	res.Path = originalPathForSandbox(res.Path, targets)
	changes, err := buildPlanChanges(targets)
	if err != nil {
		return nil, result.Result{}, sources, err
	}

	plan, err := fixplan.NewPlan(changes, sourceReports(sources, configuredSourceNames(cmd)), dependencyProvenance(sources, res))
	if err != nil {
		return nil, result.Result{}, sources, err
	}
	plan.Upgrades = planUpgrades(res)
	plan.Vulnerabilities = planVulnerabilities(res)
	plan.FixedVulnerabilityIDs = fixedVulnIDs(res)
	// Recompute identity after adding semantic summary fields.
	fixplan.RecomputeID(plan)

	return plan, res, sources, nil
}

func snapshotPlanTargets(manifest, lockfile string) ([]originalTarget, error) {
	var targets []originalTarget
	for _, path := range []string{manifest, lockfile} {
		if path == "" {
			continue
		}
		b, mode, _, err := fixplan.SnapshotFile(path)
		if err != nil {
			return nil, err
		}
		abs, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		targets = append(targets, originalTarget{original: path, abs: filepath.Clean(abs), display: path, before: b, mode: mode})
	}

	return targets, nil
}

func sandboxPathFor(original string, targets []originalTarget) string {
	abs, _ := filepath.Abs(original)
	abs = filepath.Clean(abs)
	for _, t := range targets {
		if t.abs == abs {
			return t.sandbox
		}
	}

	return filepath.Join(filepath.Dir(original), filepath.Base(original)+".sandbox")
}

func originalPathForSandbox(path string, targets []originalTarget) string {
	for _, t := range targets {
		if path == t.sandbox {
			return t.original
		}
	}

	return path
}

func buildPlanChanges(targets []originalTarget) ([]fixplan.FileChange, error) {
	var changes []fixplan.FileChange
	for _, t := range targets {
		after, err := os.ReadFile(t.sandbox)
		deleteFile := false
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			deleteFile = true
			after = nil
		}
		if !deleteFile && string(after) == string(t.before) {
			continue
		}
		fc, err := fixplan.NewFileChange(t.abs, t.display, t.before, t.mode, after)
		if err != nil {
			return nil, err
		}
		changes = append(changes, fc)
	}

	return changes, nil
}

func allSourcesUnavailable(reports []fixplan.SourceReport) bool {
	if len(reports) == 0 {
		return false
	}
	for _, r := range reports {
		if r.Status != "unavailable" {
			return false
		}
	}

	return true
}

func sourceReports(setup *resolveSourceSetup, names []string) []fixplan.SourceReport {
	if setup != nil && setup.router != nil {
		return setup.router.Reports()
	}
	name := "deps.dev"
	if len(names) > 0 {
		name = names[0]
	}

	return []fixplan.SourceReport{{Name: sourceLabel(name, 0), Priority: 0, Status: "available"}}
}

func dependencyProvenance(setup *resolveSourceSetup, res result.Result) []fixplan.DependencyProvenance {
	if setup != nil && setup.router != nil {
		return setup.router.Provenance()
	}
	source := "deps.dev"
	if len(sourceNamesFromSetup(setup)) > 0 {
		source = sourceNamesFromSetup(setup)[0]
	}
	var out []fixplan.DependencyProvenance
	for _, p := range res.Patches {
		for _, u := range p.PackageUpdates {
			out = append(out, fixplan.DependencyProvenance{
				Key:             string(res.Ecosystem) + "/" + u.Name,
				Ecosystem:       string(res.Ecosystem),
				Name:            u.Name,
				SelectedSource:  source,
				SelectionReason: "single_configured_source",
			})
		}
	}

	return out
}

func sourceNamesFromSetup(setup *resolveSourceSetup) []string {
	if setup == nil || setup.router == nil {
		return nil
	}

	return setup.router.Sources()
}

func planUpgrades(res result.Result) []fixplan.Upgrade {
	var out []fixplan.Upgrade
	for _, p := range res.Patches {
		for _, u := range p.PackageUpdates {
			out = append(out, fixplan.Upgrade{
				Name:        u.Name,
				VersionFrom: u.VersionFrom,
				VersionTo:   u.VersionTo,
				Ecosystem:   string(res.Ecosystem),
			})
		}
	}

	return out
}

func planVulnerabilities(res result.Result) []fixplan.Vulnerability {
	out := make([]fixplan.Vulnerability, 0, len(res.Vulnerabilities))
	for _, v := range res.Vulnerabilities {
		out = append(out, fixplan.Vulnerability{ID: v.ID, Unactionable: v.Unactionable})
	}

	return out
}

func fixedVulnIDs(res result.Result) []string {
	var out []string
	for _, p := range res.Patches {
		for _, v := range p.Fixed {
			out = append(out, v.ID)
		}
	}

	return out
}
