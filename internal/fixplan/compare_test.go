package fixplan

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestComparePlansFindsRequiredDifferences(t *testing.T) {
	t.Parallel()
	a, err := NewPlan(nil, []SourceReport{{Name: "deps.dev", Priority: 0, Status: "available"}}, []DependencyProvenance{
		{Key: "npm/one", Name: "one", SelectedSource: "deps.dev"},
		{Key: "npm/shared", Name: "shared", SelectedSource: "deps.dev"},
	})
	if err != nil {
		t.Fatal(err)
	}
	a.Upgrades = []Upgrade{
		{Name: "shared", VersionFrom: "1.0.0", VersionTo: "1.2.0"},
		{Name: "only-a", VersionFrom: "1.0.0", VersionTo: "2.0.0"},
	}
	a.FixedVulnerabilityIDs = []string{"CVE-SHARED", "GHSA-ONLY-A"}
	RecomputeID(a)

	b, err := NewPlan(nil, []SourceReport{{Name: "native", Priority: 0, Status: "available"}}, []DependencyProvenance{
		{Key: "npm/shared", Name: "shared", SelectedSource: "native"},
		{Key: "npm/two", Name: "two", SelectedSource: "native"},
	})
	if err != nil {
		t.Fatal(err)
	}
	b.Upgrades = []Upgrade{
		{Name: "shared", VersionFrom: "1.0.0", VersionTo: "1.3.0"},
		{Name: "only-b", VersionFrom: "1.0.0", VersionTo: "3.0.0"},
	}
	b.FixedVulnerabilityIDs = []string{"CVE-SHARED", "GHSA-ONLY-B"}
	RecomputeID(b)

	cmp := ComparePlans(a, b)
	if !cmp.HasDifferences {
		t.Fatal("expected differences")
	}
	if len(cmp.VersionDifferences) != 1 || cmp.VersionDifferences[0].VersionToA != "1.2.0" || cmp.VersionDifferences[0].VersionToB != "1.3.0" {
		t.Fatalf("version differences = %+v", cmp.VersionDifferences)
	}
	if strings.Join(cmp.FixedOnlyInA, ",") != "GHSA-ONLY-A" {
		t.Fatalf("fixed only A = %v", cmp.FixedOnlyInA)
	}
	if strings.Join(cmp.FixedOnlyInB, ",") != "GHSA-ONLY-B" {
		t.Fatalf("fixed only B = %v", cmp.FixedOnlyInB)
	}
	if len(cmp.UpgradeOnlyInA) != 1 || cmp.UpgradeOnlyInA[0].Name != "only-a" {
		t.Fatalf("upgrade only A = %+v", cmp.UpgradeOnlyInA)
	}
	if len(cmp.UpgradeOnlyInB) != 1 || cmp.UpgradeOnlyInB[0].Name != "only-b" {
		t.Fatalf("upgrade only B = %+v", cmp.UpgradeOnlyInB)
	}
	if !slices.Contains(cmp.DependencyOnlyInA, "one") || !slices.Contains(cmp.DependencyOnlyInB, "two") {
		t.Fatalf("dependency-only A=%v B=%v", cmp.DependencyOnlyInA, cmp.DependencyOnlyInB)
	}
	if len(cmp.SourceDifferences) != 1 || cmp.SourceDifferences[0].SourceA != "deps.dev" {
		t.Fatalf("source differences = %+v", cmp.SourceDifferences)
	}

	var text bytes.Buffer
	if err := cmp.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	out := text.String()
	for _, want := range []string{"1.2.0", "1.3.0", "GHSA-ONLY-A", "GHSA-ONLY-B", "only-a", "only-b", "one", "two"} {
		if !strings.Contains(out, want) {
			t.Fatalf("text comparison missing %q:\n%s", want, out)
		}
	}
	var jsonOut bytes.Buffer
	if err := cmp.WriteJSON(&jsonOut); err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(jsonOut.Bytes(), &decoded); err != nil {
		t.Fatalf("comparison JSON invalid: %v\n%s", err, jsonOut.String())
	}
}

func TestUnifiedDiffContainsChange(t *testing.T) {
	t.Parallel()
	diff := UnifiedDiff("package.json", []byte("{\n  \"x\": \"1.0.0\"\n}\n"), []byte("{\n  \"x\": \"2.0.0\"\n}\n"))
	if !strings.Contains(diff, `-  "x": "1.0.0"`) || !strings.Contains(diff, `+  "x": "2.0.0"`) {
		t.Fatalf("bad diff:\n%s", diff)
	}
	if UnifiedDiff("same", []byte("a\n"), []byte("a\n")) != "" {
		t.Fatal("equal inputs produced diff")
	}
}
