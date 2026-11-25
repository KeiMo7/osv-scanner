package fixplan

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// PlanComparison contains semantic differences between two plans.
type PlanComparison struct {
	PlanAID string `json:"plan_a_id"`
	PlanBID string `json:"plan_b_id"`

	VersionDifferences []VersionDifference `json:"version_differences"`
	FixedOnlyInA       []string            `json:"fixed_only_in_a"`
	FixedOnlyInB       []string            `json:"fixed_only_in_b"`
	UpgradeOnlyInA     []Upgrade           `json:"upgrade_only_in_a"`
	UpgradeOnlyInB     []Upgrade           `json:"upgrade_only_in_b"`
	DependencyOnlyInA  []string            `json:"dependency_only_in_a"`
	DependencyOnlyInB  []string            `json:"dependency_only_in_b"`
	SourceDifferences  []SourceDifference  `json:"source_differences,omitempty"`

	HasDifferences bool `json:"has_differences"`
}

// VersionDifference compares one dependency's target version.
type VersionDifference struct {
	Name         string `json:"name"`
	VersionFromA string `json:"version_from_a,omitempty"`
	VersionToA   string `json:"version_to_a,omitempty"`
	SourceA      string `json:"source_a,omitempty"`
	VersionFromB string `json:"version_from_b,omitempty"`
	VersionToB   string `json:"version_to_b,omitempty"`
	SourceB      string `json:"source_b,omitempty"`
}

// SourceDifference reports different source selection for one dependency.
type SourceDifference struct {
	Name    string `json:"name"`
	SourceA string `json:"source_a"`
	SourceB string `json:"source_b"`
}

// ComparePlans computes sorted, deterministic semantic differences.
func ComparePlans(a, b *Plan) PlanComparison {
	cmp := PlanComparison{PlanAID: a.ID, PlanBID: b.ID}

	upA := upgradeMap(a.Upgrades)
	upB := upgradeMap(b.Upgrades)
	for name, ua := range upA {
		ub, ok := upB[name]
		if !ok {
			cmp.UpgradeOnlyInA = append(cmp.UpgradeOnlyInA, ua)
			continue
		}
		if ua.VersionTo != ub.VersionTo || ua.VersionFrom != ub.VersionFrom {
			cmp.VersionDifferences = append(cmp.VersionDifferences, VersionDifference{
				Name:         name,
				VersionFromA: ua.VersionFrom,
				VersionToA:   ua.VersionTo,
				SourceA:      sourceFor(a, name),
				VersionFromB: ub.VersionFrom,
				VersionToB:   ub.VersionTo,
				SourceB:      sourceFor(b, name),
			})
		}
	}
	for name, ub := range upB {
		if _, ok := upA[name]; !ok {
			cmp.UpgradeOnlyInB = append(cmp.UpgradeOnlyInB, ub)
		}
	}

	fixedA := sortedSet(a.FixedVulnerabilityIDs)
	fixedB := sortedSet(b.FixedVulnerabilityIDs)
	cmp.FixedOnlyInA = setDifference(fixedA, fixedB)
	cmp.FixedOnlyInB = setDifference(fixedB, fixedA)

	depA := dependencyMap(a.Dependencies)
	depB := dependencyMap(b.Dependencies)
	for key, da := range depA {
		db, ok := depB[key]
		if !ok {
			cmp.DependencyOnlyInA = append(cmp.DependencyOnlyInA, depLabel(key, da))
			continue
		}
		if da.SelectedSource != db.SelectedSource && (da.SelectedSource != "" || db.SelectedSource != "") {
			cmp.SourceDifferences = append(cmp.SourceDifferences, SourceDifference{
				Name:    depLabel(key, da),
				SourceA: da.SelectedSource,
				SourceB: db.SelectedSource,
			})
		}
	}
	for key, db := range depB {
		if _, ok := depA[key]; !ok {
			cmp.DependencyOnlyInB = append(cmp.DependencyOnlyInB, depLabel(key, db))
		}
	}

	slices.SortFunc(cmp.VersionDifferences, func(x, y VersionDifference) int { return strings.Compare(x.Name, y.Name) })
	slices.SortFunc(cmp.UpgradeOnlyInA, compareUpgrade)
	slices.SortFunc(cmp.UpgradeOnlyInB, compareUpgrade)
	slices.Sort(cmp.FixedOnlyInA)
	slices.Sort(cmp.FixedOnlyInB)
	slices.Sort(cmp.DependencyOnlyInA)
	slices.Sort(cmp.DependencyOnlyInB)
	slices.SortFunc(cmp.SourceDifferences, func(x, y SourceDifference) int { return strings.Compare(x.Name, y.Name) })

	cmp.HasDifferences = len(cmp.VersionDifferences)+len(cmp.FixedOnlyInA)+len(cmp.FixedOnlyInB)+
		len(cmp.UpgradeOnlyInA)+len(cmp.UpgradeOnlyInB)+len(cmp.DependencyOnlyInA)+len(cmp.DependencyOnlyInB)+
		len(cmp.SourceDifferences) > 0

	return cmp
}

// WriteText writes a stable human-readable comparison.
func (c PlanComparison) WriteText(w io.Writer) error {
	if !c.HasDifferences {
		_, err := fmt.Fprintln(w, "Plans are semantically identical.")
		return err
	}

	var lines []string
	lines = append(lines, "Plan comparison:")
	if len(c.VersionDifferences) > 0 {
		lines = append(lines, "", "Target version differences:")
		for _, d := range c.VersionDifferences {
			src := ""
			if d.SourceA != "" || d.SourceB != "" {
				src = fmt.Sprintf(" [source %s vs %s]", orDash(d.SourceA), orDash(d.SourceB))
			}
			lines = append(lines, fmt.Sprintf("  %s: %s -> %s (plan %s) vs %s -> %s (plan %s)%s",
				d.Name, orDash(d.VersionFromA), orDash(d.VersionToA), shortPlan(c.PlanAID),
				orDash(d.VersionFromB), orDash(d.VersionToB), shortPlan(c.PlanBID), src))
		}
	}
	if len(c.FixedOnlyInA) > 0 {
		lines = append(lines, "", "Vulnerabilities fixable only in first plan:")
		for _, id := range c.FixedOnlyInA {
			lines = append(lines, "  "+id)
		}
	}
	if len(c.FixedOnlyInB) > 0 {
		lines = append(lines, "", "Vulnerabilities fixable only in second plan:")
		for _, id := range c.FixedOnlyInB {
			lines = append(lines, "  "+id)
		}
	}
	if len(c.UpgradeOnlyInA) > 0 {
		lines = append(lines, "", "Dependencies changed only in first plan:")
		for _, u := range c.UpgradeOnlyInA {
			lines = append(lines, "  "+formatUpgrade(u))
		}
	}
	if len(c.UpgradeOnlyInB) > 0 {
		lines = append(lines, "", "Dependencies changed only in second plan:")
		for _, u := range c.UpgradeOnlyInB {
			lines = append(lines, "  "+formatUpgrade(u))
		}
	}
	if len(c.DependencyOnlyInA) > 0 {
		lines = append(lines, "", "Dependencies present only in first plan:")
		for _, d := range c.DependencyOnlyInA {
			lines = append(lines, "  "+d)
		}
	}
	if len(c.DependencyOnlyInB) > 0 {
		lines = append(lines, "", "Dependencies present only in second plan:")
		for _, d := range c.DependencyOnlyInB {
			lines = append(lines, "  "+d)
		}
	}
	if len(c.SourceDifferences) > 0 {
		lines = append(lines, "", "Source selection differences:")
		for _, d := range c.SourceDifferences {
			lines = append(lines, fmt.Sprintf("  %s: %s vs %s", d.Name, orDash(d.SourceA), orDash(d.SourceB)))
		}
	}

	_, err := io.WriteString(w, strings.Join(lines, "\n")+"\n")

	return err
}

// WriteJSON writes indented comparison JSON.
func (c PlanComparison) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(c)
}

func upgradeMap(in []Upgrade) map[string]Upgrade {
	out := make(map[string]Upgrade, len(in))
	for _, u := range in {
		out[normalizeDepName(u.Name)] = u
	}

	return out
}

func normalizeDepName(name string) string {
	// Maven coordinates and package names are compared exactly after trimming.
	return strings.TrimSpace(name)
}

func compareUpgrade(a, b Upgrade) int {
	if c := strings.Compare(normalizeDepName(a.Name), normalizeDepName(b.Name)); c != 0 {
		return c
	}

	return strings.Compare(a.VersionTo, b.VersionTo)
}

func formatUpgrade(u Upgrade) string {
	if u.VersionFrom == "" {
		return fmt.Sprintf("%s -> %s", u.Name, u.VersionTo)
	}

	return fmt.Sprintf("%s: %s -> %s", u.Name, u.VersionFrom, u.VersionTo)
}

func sourceFor(p *Plan, name string) string {
	key := normalizeDepName(name)
	for _, d := range p.Dependencies {
		if normalizeDepName(d.Name) == key || normalizeDepName(d.Key) == key {
			return d.SelectedSource
		}
	}

	return ""
}

func dependencyMap(in []DependencyProvenance) map[string]DependencyProvenance {
	out := make(map[string]DependencyProvenance, len(in))
	for _, d := range in {
		key := d.Key
		if key == "" {
			key = d.Ecosystem + "/" + d.Name
		}
		out[key] = d
	}

	return out
}

func depLabel(key string, d DependencyProvenance) string {
	if d.Name != "" {
		return d.Name
	}

	return key
}

func sortedSet(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)

	return slices.Compact(out)
}

func setDifference(a, b []string) []string {
	bSet := make(map[string]struct{}, len(b))
	for _, x := range b {
		bSet[x] = struct{}{}
	}
	var out []string
	for _, x := range a {
		if _, ok := bSet[x]; !ok {
			out = append(out, x)
		}
	}
	slices.Sort(out)

	return slices.Compact(out)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}

	return s
}

func shortPlan(id string) string {
	parts := strings.Split(id, "-")
	if len(parts) >= 2 && len(parts[1]) > 8 {
		return parts[1][:8]
	}

	return orDash(id)
}
