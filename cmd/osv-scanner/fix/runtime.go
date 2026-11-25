package fix

import (
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	scalibrosvdev "github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvlocal"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scanner/v2/internal/version"
	"github.com/google/osv-scanner/v2/pkg/osvscanner"
	"github.com/urfave/cli/v3"
)

func buildFixOptions(cmd *cli.Command) options.FixVulnsOptions {
	opts := options.FixVulnsOptions{
		MavenManagement:   cmd.Bool("maven-fix-management"),
		IgnoreVulns:       cmd.StringSlice("ignore-vulns"),
		ExplicitVulns:     cmd.StringSlice("vulns"),
		DevDeps:           !cmd.Bool("ignore-dev"),
		MinSeverity:       cmd.Float64("min-severity"),
		MaxDepth:          cmd.Int("max-depth"),
		UpgradeConfig:     upgrade.NewConfigFromStrings(cmd.StringSlice("upgrade-config")),
		Manifest:          cmd.String("manifest"),
		Lockfile:          cmd.String("lockfile"),
		Strategy:          strategy.Strategy(cmd.String("strategy")),
		MaxUpgrades:       cmd.Int("apply-top"),
		NoIntroduce:       cmd.Bool("no-introduce"),
		NoMavenNewDepMgmt: false,
	}
	if opts.Strategy == "relock" {
		opts.Strategy = strategy.StrategyRelax
	}

	return opts
}

func userAgent() string {
	return "osv-scanner_fix/" + version.OSVVersion
}

func setupFactories(clientFactories config.ClientFactories, ua string) (config.ClientFactories, func()) {
	return osvscanner.SetupClientFactories(clientFactories, nil, ua)
}

func buildVulnEnricher(cmd *cli.Command, cf config.ClientFactories, ua string) (enricher.Enricher, error) {
	cfg := &cpb.PluginConfig{
		UserAgent: ua,
		PluginSpecific: []*cpb.PluginSpecificConfig{
			{Config: &cpb.PluginSpecificConfig_Osvlocal{Osvlocal: &cpb.OSVLocalConfig{
				Download:   cmd.Bool("download-offline-databases"),
				LocalPath:  cmd.String("local-db-path"),
				RemoteHost: "https://osv-vulnerabilities.storage.googleapis.com",
			}}},
		},
	}
	pluginCfg := &config.PluginConfig{ProtoConfig: cfg, ClientFactories: cf}
	if cmd.Bool("offline-vulnerabilities") {
		return osvlocal.New(pluginCfg)
	}

	return scalibrosvdev.New(pluginCfg)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}

	return ""
}
