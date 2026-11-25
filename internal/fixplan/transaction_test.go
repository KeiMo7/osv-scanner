package fixplan

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scanner/v2/internal/testutility"
)

type plannedFiles struct {
	plan   *Plan
	paths  []string
	before [][]byte
	after  [][]byte
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTwoFilePlan(t *testing.T) plannedFiles {
	t.Helper()
	root := t.TempDir()
	paths := []string{filepath.Join(root, "a", "manifest.txt"), filepath.Join(root, "b", "lock.txt")}
	before := [][]byte{[]byte("manifest before\n"), []byte("lock before\n")}
	after := [][]byte{[]byte("manifest after\n"), []byte("lock after\n")}

	changes := make([]FileChange, 0, len(paths))
	for i, path := range paths {
		writeTestFile(t, path, before[i])
		fc, err := NewFileChange(path, filepath.Base(path), before[i], 0o644, after[i])
		if err != nil {
			t.Fatal(err)
		}
		changes = append(changes, fc)
	}
	plan, err := NewPlan(changes, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	return plannedFiles{plan: plan, paths: paths, before: before, after: after}
}

func (p plannedFiles) assertBytes(t *testing.T, want [][]byte) {
	t.Helper()
	for i, path := range p.paths {
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		if string(got) != string(want[i]) {
			t.Fatalf("%s bytes = %q, want %q", path, got, want[i])
		}
	}
}

func TestApplyPlanSuccessAndIdempotent(t *testing.T) {
	t.Parallel()
	pf := newTwoFilePlan(t)
	stateDir := filepath.Join(t.TempDir(), "state")

	report, err := ApplyPlan(pf.plan, ApplyOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("ApplyPlan: %v", err)
	}
	if len(report.Applied) != 2 {
		t.Fatalf("Applied = %+v", report.Applied)
	}
	pf.assertBytes(t, pf.after)

	report2, err := ApplyPlan(pf.plan, ApplyOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("idempotent ApplyPlan: %v", err)
	}
	if len(report2.AlreadyApplied) != 2 || len(report2.Applied) != 0 {
		t.Fatalf("second report = %+v", report2)
	}
	entries, _ := os.ReadDir(stateDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tx-") {
			t.Fatalf("transaction directory survived successful apply: %s", e.Name())
		}
	}
}

func TestApplyPlanConflictRejectsAll(t *testing.T) {
	t.Parallel()
	pf := newTwoFilePlan(t)
	if err := os.WriteFile(pf.paths[0], []byte("user changed this\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := ApplyPlan(pf.plan, ApplyOptions{StateDir: t.TempDir()})
	if !IsConflict(err) {
		t.Fatalf("expected conflict error, got %v", err)
	}
	var ae *ApplyError
	if !errors.As(err, &ae) || len(ae.Conflicts) != 1 {
		t.Fatalf("conflict details = %+v", err)
	}
	if ae.Conflicts[0].DisplayPath == "" {
		t.Fatal("conflict is missing display path")
	}
	got, _ := os.ReadFile(pf.paths[0])
	if string(got) != "user changed this\n" {
		t.Fatalf("conflicting file was overwritten: %q", got)
	}
	got1, _ := os.ReadFile(pf.paths[1])
	if string(got1) != string(pf.before[1]) {
		t.Fatalf("non-conflicting file changed before rejection: %q", got1)
	}
}

func TestApplyPlanRollsBackAfterWriteFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		testutility.Skip(t, "read-only directory injection is unix-specific")
	}
	if os.Geteuid() == 0 {
		testutility.Skip(t, "root bypasses directory permissions")
	}
	t.Parallel()
	pf := newTwoFilePlan(t)
	readOnlyDir := filepath.Dir(pf.paths[1])
	if err := os.Chmod(readOnlyDir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnlyDir, 0o755) })

	stateDir := filepath.Join(t.TempDir(), "state")
	_, err := ApplyPlan(pf.plan, ApplyOptions{StateDir: stateDir})
	if err == nil {
		t.Fatal("expected second file write to fail")
	}
	if strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Fatalf("raw filesystem error leaked to user: %v", err)
	}

	pf.assertBytes(t, pf.before)
	for _, path := range pf.paths {
		dir := filepath.Dir(path)
		matches, err := filepath.Glob(filepath.Join(dir, ".osv-scanner-fix-*"))
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) != 0 {
			t.Fatalf("temporary files remain in %s: %v", dir, matches)
		}
	}
	entries, _ := os.ReadDir(stateDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "tx-") {
			t.Fatalf("transaction directory survived rollback: %s", e.Name())
		}
	}
}

func TestRecoverInterruptedTransaction(t *testing.T) {
	t.Parallel()
	pf := newTwoFilePlan(t)
	stateDir := filepath.Join(t.TempDir(), "state")
	txDir := filepath.Join(stateDir, "tx-plan-interrupted")
	if err := os.MkdirAll(txDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// The first file had already been written when the process died.
	if err := os.WriteFile(pf.paths[0], pf.after[0], 0o600); err != nil {
		t.Fatal(err)
	}
	for i := range pf.paths {
		backup := filepath.Join(txDir, "backup-00"+string(rune('0'+i))+".bin")
		if err := os.WriteFile(backup, pf.before[i], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	j := Journal{
		ID:     "tx-plan-interrupted",
		PlanID: pf.plan.ID,
		Status: "prepared",
		Files: []JournalFile{
			{Path: pf.paths[0], DisplayPath: "manifest.txt", BeforeSHA256: HashBytes(pf.before[0]), Mode: 0o644, Existed: true, BackupName: "backup-000.bin"},
			{Path: pf.paths[1], DisplayPath: "lock.txt", BeforeSHA256: HashBytes(pf.before[1]), Mode: 0o644, Existed: true, BackupName: "backup-001.bin"},
		},
	}
	if err := writeJournal(txDir, &j); err != nil {
		t.Fatal(err)
	}

	recovered, err := Recover(ApplyOptions{StateDir: stateDir})
	if err != nil {
		t.Fatalf("Recover: %v", err)
	}
	if len(recovered) != 1 || recovered[0] != j.ID {
		t.Fatalf("recovered = %+v", recovered)
	}
	pf.assertBytes(t, pf.before)
	if _, err := os.Stat(txDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transaction dir still exists: %v", err)
	}
}

func TestRecoverUnreadableJournalRequiresManualAction(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	bad := filepath.Join(stateDir, "tx-bad-journal")
	if err := os.MkdirAll(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "journal.json"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Recover(ApplyOptions{StateDir: stateDir})
	if !IsRecoveryRequired(err) {
		t.Fatalf("expected recovery-required error, got %v", err)
	}
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.BackupDir != bad || !strings.Contains(ae.Recovery, bad) {
		t.Fatalf("error does not identify exact recovery location: %+v", err)
	}
}

func TestApplyLockSecondHolderFails(t *testing.T) {
	t.Parallel()
	stateDir := t.TempDir()
	lock, err := acquireApplyLock(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Release() //nolint:errcheck

	_, err = acquireApplyLock(stateDir)
	var ae *ApplyError
	if !errors.As(err, &ae) || ae.Code != CodeLocked {
		t.Fatalf("expected locked error, got %v", err)
	}
}
