package fix_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func TestPlanSubcommandDryRunWritesNothingOriginal(t *testing.T) {
	testDir := testutility.CreateTestDir(t)
	tmpRoot := filepath.Join(testDir, "tmp")
	if err := os.MkdirAll(tmpRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", tmpRoot)

	planPath := filepath.Join(testDir, "review-plan.json")
	tc := testcmd.Case{
		Name: "plan_dry_run_relax_package",
		Args: []string{
			"", "fix", "plan",
			"--strategy=relax",
			"-M", "./testdata/relax-npm/package.json",
			"--plan-out", planPath,
		},
		Exit:         0,
		CassetteName: "TestCommand_fix_non-interactive_relax_package.json",
	}
	manifest := testcmd.CopyFileFlagTo(t, tc, "-M", testDir)
	beforeHash, err := fixplan.HashFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}

	stdout, stderr := testcmd.RunAndNormalize(t, tc)

	afterHash, err := fixplan.HashFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if afterHash != beforeHash {
		t.Fatalf("manifest changed during dry run:\nbefore hash %s\nafter hash %s", beforeHash, afterHash)
	}
	afterBytes, _ := os.ReadFile(manifest)
	if string(afterBytes) != string(beforeBytes) {
		t.Fatal("manifest bytes changed during dry run")
	}

	plan, err := fixplan.LoadPlanFile(planPath)
	if err != nil {
		t.Fatalf("planned file was not written: %v\nstdout:%s\nstderr:%s", err, stdout, stderr)
	}
	if len(plan.Files) != 1 {
		t.Fatalf("plan files = %d, want 1: %+v", len(plan.Files), plan)
	}
	if plan.Files[0].UnifiedDiff == "" || !testContains(plan.Files[0].UnifiedDiff, `npm-registry-client`) {
		t.Fatalf("plan diff missing dependency change:\n%s", plan.Files[0].UnifiedDiff)
	}
	if !testContains(stdout, "PLAN-ID:") || !testContains(stdout, "--- a/") {
		t.Fatalf("stdout missing plan id/diff:\n%s\nstderr:%s", stdout, stderr)
	}

	entries, err := os.ReadDir(tmpRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if testContains(e.Name(), "osv-scanner-fix-plan-") {
			t.Fatalf("sandbox temp directory survived dry run: %s", e.Name())
		}
	}
	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(manifest), ".osv-scanner-fix-*"))
	if len(matches) != 0 {
		t.Fatalf("temp files next to manifest: %v", matches)
	}
}

func testContains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}

		return false
	}())
}
