package fix_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/google/osv-scanner/v2/internal/testutility"
)

func runWorkflowCLI(t *testing.T, args []string, exit int) (string, string) {
	t.Helper()

	return testcmd.RunAndNormalize(t, testcmd.Case{
		Name:         t.Name(),
		Args:         args,
		Exit:         exit,
		CassetteName: testcmd.NoInteractions,
	})
}

func workflowPlan(t *testing.T, root string) (*fixplan.Plan, []string, [][]byte, [][]byte) {
	t.Helper()
	paths := []string{filepath.Join(root, "first", "a.txt"), filepath.Join(root, "second", "b.txt")}
	before := [][]byte{[]byte("first before\n"), []byte("second before\n")}
	after := [][]byte{[]byte("first after\n"), []byte("second after\n")}
	changes := make([]fixplan.FileChange, 0, len(paths))
	for i, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, before[i], 0o600); err != nil {
			t.Fatal(err)
		}
		fc, err := fixplan.NewFileChange(path, filepath.Base(path), before[i], 0o644, after[i])
		if err != nil {
			t.Fatal(err)
		}
		changes = append(changes, fc)
	}
	plan, err := fixplan.NewPlan(changes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	planPath := filepath.Join(root, "plan.json")
	if err := fixplan.WritePlanFile(planPath, plan); err != nil {
		t.Fatal(err)
	}

	return plan, paths, before, after
}

func assertWorkflowBytes(t *testing.T, paths []string, want [][]byte) {
	t.Helper()
	for i, p := range paths {
		got, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want[i]) {
			t.Fatalf("%s = %q, want %q", p, got, want[i])
		}
	}
}

func TestPlanApplyCommandSuccessIdempotentAndJSON(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, paths, _, after := workflowPlan(t, root)
	planPath := filepath.Join(root, "plan.json")
	stateDir := filepath.Join(root, "state")

	stdout, _ := runWorkflowCLI(t, []string{"", "fix", "apply", "--plan", planPath, "--state-dir", stateDir}, 0)
	if !strings.Contains(stdout, "APPLY-OK") || !strings.Contains(stdout, "APPLIED: a.txt") {
		t.Fatalf("unexpected apply stdout:\n%s", stdout)
	}
	assertWorkflowBytes(t, paths, after)

	stdout2, _ := runWorkflowCLI(t, []string{"", "fix", "apply", "--plan", planPath, "--state-dir", stateDir}, 0)
	if !strings.Contains(stdout2, "ALREADY-APPLIED: a.txt") {
		t.Fatalf("second apply was not idempotent:\n%s", stdout2)
	}

	jsonOut, _ := runWorkflowCLI(t, []string{"", "fix", "apply", "--plan", planPath, "--state-dir", stateDir, "--format=json"}, 0)
	var decoded struct {
		OK     bool `json:"ok"`
		Report struct {
			AlreadyApplied []string `json:"already_applied"`
		} `json:"report"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("apply JSON invalid: %v\n%s", err, jsonOut)
	}
	if !decoded.OK || len(decoded.Report.AlreadyApplied) != 2 {
		t.Fatalf("unexpected apply JSON:\n%s", jsonOut)
	}
}

func TestPlanApplyCommandConflict(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, paths, before, _ := workflowPlan(t, root)
	planPath := filepath.Join(root, "plan.json")
	if err := os.WriteFile(paths[0], []byte("manual edit\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, stderr := runWorkflowCLI(t, []string{
		"", "fix", "apply", "--plan", planPath, "--state-dir", filepath.Join(root, "state"),
	}, 127)
	combined := stdout + stderr
	if !strings.Contains(combined, "changed after plan generation") || !strings.Contains(combined, "a.txt") {
		t.Fatalf("expected conflict details, got:\nstdout:%s\nstderr:%s", stdout, stderr)
	}
	got, _ := os.ReadFile(paths[0])
	if string(got) != "manual edit\n" {
		t.Fatalf("conflict file overwritten: %q", got)
	}
	got1, _ := os.ReadFile(paths[1])
	if string(got1) != string(before[1]) {
		t.Fatalf("second file changed: %q", got1)
	}
}

func TestPlanApplyCommandRollbackOnReadOnlyDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		testutility.Skip(t, "unix permissions test")
	}
	if os.Geteuid() == 0 {
		testutility.Skip(t, "root bypasses permissions")
	}
	root := t.TempDir()
	_, paths, before, _ := workflowPlan(t, root)
	readOnlyDir := filepath.Dir(paths[1])
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0o755) })

	stateDir := filepath.Join(root, "state")
	stdout, stderr := runWorkflowCLI(t, []string{"", "fix", "apply", "--plan", filepath.Join(root, "plan.json"), "--state-dir", stateDir}, 127)
	combined := stdout + stderr
	if strings.Contains(strings.ToLower(combined), "permission denied") {
		t.Fatalf("raw filesystem error leaked:\n%s", combined)
	}
	if !strings.Contains(combined, "restored to their pre-apply bytes") {
		t.Fatalf("expected rollback message:\n%s", combined)
	}
	assertWorkflowBytes(t, paths, before)
	for _, p := range paths {
		matches, err := filepath.Glob(filepath.Join(filepath.Dir(p), ".osv-scanner-fix-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("temp files remain: %v", matches)
		}
	}
}

func TestPlanApplyCommandInterruptedRecovery(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	plan, paths, before, after := workflowPlan(t, root)
	stateDir := filepath.Join(root, "state")
	txDir := filepath.Join(stateDir, "tx-command-interrupted")
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths[0], after[0], 0o600); err != nil {
		t.Fatal(err)
	}
	for i, b := range before {
		name := filepath.Join(txDir, "backup-00"+string(rune('0'+i))+".bin")
		if err := os.WriteFile(name, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j := fixplan.Journal{ID: "tx-command-interrupted", PlanID: plan.ID, Status: "prepared", Files: []fixplan.JournalFile{
		{Path: paths[0], DisplayPath: "a.txt", BeforeSHA256: fixplan.HashBytes(before[0]), Mode: 0o644, Existed: true, BackupName: "backup-000.bin"},
		{Path: paths[1], DisplayPath: "b.txt", BeforeSHA256: fixplan.HashBytes(before[1]), Mode: 0o644, Existed: true, BackupName: "backup-001.bin"},
	}}
	jb, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(txDir, "journal.json"), jb, 0o600); err != nil {
		t.Fatal(err)
	}

	stdout, _ := runWorkflowCLI(t, []string{"", "fix", "apply", "--plan", filepath.Join(root, "plan.json"), "--state-dir", stateDir}, 0)
	if !strings.Contains(stdout, "RECOVERED-TRANSACTION: tx-command-interrupted") {
		t.Fatalf("missing recovery notice:\n%s", stdout)
	}
	assertWorkflowBytes(t, paths, after)
}

func TestPlanCompareCommand(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	a, err := fixplan.NewPlan(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a.Upgrades = []fixplan.Upgrade{{Name: "shared", VersionFrom: "1.0.0", VersionTo: "1.1.0"}, {Name: "only-a", VersionTo: "2.0.0"}}
	a.FixedVulnerabilityIDs = []string{"GHSA-A"}
	fixplan.RecomputeID(a)
	b, _ := fixplan.NewPlan(nil, nil, nil)
	b.Upgrades = []fixplan.Upgrade{{Name: "shared", VersionFrom: "1.0.0", VersionTo: "1.2.0"}, {Name: "only-b", VersionTo: "3.0.0"}}
	b.FixedVulnerabilityIDs = []string{"GHSA-B"}
	fixplan.RecomputeID(b)
	pa := filepath.Join(root, "a.json")
	pb := filepath.Join(root, "b.json")
	if err := fixplan.WritePlanFile(pa, a); err != nil {
		t.Fatal(err)
	}
	if err := fixplan.WritePlanFile(pb, b); err != nil {
		t.Fatal(err)
	}

	stdout, _ := runWorkflowCLI(t, []string{"", "fix", "compare", pa, pb, "--format=json"}, 0)
	var cmp fixplan.PlanComparison
	if err := json.Unmarshal([]byte(stdout), &cmp); err != nil {
		t.Fatalf("compare JSON: %v\n%s", err, stdout)
	}
	if len(cmp.VersionDifferences) != 1 || cmp.VersionDifferences[0].VersionToA != "1.1.0" {
		t.Fatalf("version diffs = %+v", cmp.VersionDifferences)
	}
	if !slices.Contains(cmp.FixedOnlyInA, "GHSA-A") || !slices.Contains(cmp.FixedOnlyInB, "GHSA-B") {
		t.Fatalf("vuln diffs = %+v / %+v", cmp.FixedOnlyInA, cmp.FixedOnlyInB)
	}
	if len(cmp.UpgradeOnlyInA) != 1 || len(cmp.UpgradeOnlyInB) != 1 {
		t.Fatalf("dependency diffs = %+v %+v", cmp.UpgradeOnlyInA, cmp.UpgradeOnlyInB)
	}

	textOut, _ := runWorkflowCLI(t, []string{"", "fix", "compare", pa, pb}, 0)
	for _, want := range []string{"1.1.0", "1.2.0", "GHSA-A", "GHSA-B", "only-a", "only-b"} {
		if !strings.Contains(textOut, want) {
			t.Fatalf("text comparison missing %q:\n%s", want, textOut)
		}
	}
}
