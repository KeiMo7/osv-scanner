package fixplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// ApplyOptions controls plan application.
type ApplyOptions struct {
	// StateDir contains locks, journals, and recoverable backups. Empty uses
	// OSV_SCANNER_FIX_STATE_DIR or the user cache directory.
	StateDir string
}

// ApplyReport describes an application attempt.
type ApplyReport struct {
	PlanID         string   `json:"plan_id"`
	TransactionID  string   `json:"transaction_id,omitempty"`
	Applied        []string `json:"applied"`
	AlreadyApplied []string `json:"already_applied"`
	Recovered      []string `json:"recovered_transactions,omitempty"`
	StateDir       string   `json:"state_dir"`
}

// Journal is the on-disk transaction record. Its JSON format is part of the
// crash-recovery contract.
type Journal struct {
	ID        string        `json:"id"`
	PlanID    string        `json:"plan_id"`
	Status    string        `json:"status"`
	CreatedAt time.Time     `json:"created_at"`
	Files     []JournalFile `json:"files"`
}

// JournalFile records one backed-up target.
type JournalFile struct {
	Path         string `json:"path"`
	DisplayPath  string `json:"display_path"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
	Mode         uint32 `json:"mode"`
	Delete       bool   `json:"delete,omitempty"`
	Existed      bool   `json:"existed"`
	BackupName   string `json:"backup_name,omitempty"`
	NewName      string `json:"new_name,omitempty"`
}

type currentState struct {
	b      []byte
	exists bool
	hash   string
	mode   os.FileMode
}

// DefaultStateDir returns the per-user transaction state directory.
func DefaultStateDir() (string, error) {
	if v := os.Getenv("OSV_SCANNER_FIX_STATE_DIR"); v != "" {
		return filepath.Abs(v)
	}
	cache, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	return filepath.Join(cache, "osv-scanner", "fix-transactions"), nil
}

// ApplyPlan validates all targets, applies the plan in sorted target order, and
// rolls every target back if any write fails. Pending interrupted transactions
// are recovered before new validation.
func ApplyPlan(plan *Plan, opts ApplyOptions) (*ApplyReport, error) {
	if err := plan.Validate(); err != nil {
		return nil, &ApplyError{Code: "INVALID_PLAN", Message: "invalid fix plan", Cause: err}
	}
	stateDir, err := resolveStateDir(opts.StateDir)
	if err != nil {
		return nil, &ApplyError{Code: CodeRecoveryRequired, Message: "cannot determine transaction state directory", Cause: err}
	}

	lock, err := acquireApplyLock(stateDir)
	if err != nil {
		return nil, err
	}
	defer lock.Release() //nolint:errcheck // Lock release errors do not affect completed application.

	recovered, err := recoverPendingLocked(stateDir)
	if err != nil {
		return nil, err
	}

	report := &ApplyReport{PlanID: plan.ID, StateDir: stateDir, Recovered: recovered}
	states, applyChanges, conflicts, err := validateTargets(plan)
	if err != nil {
		return nil, err
	}
	if len(conflicts) > 0 {
		return nil, &ApplyError{
			Code:      CodeConflict,
			Message:   "refusing to apply plan because one or more files changed after plan generation",
			Conflicts: conflicts,
		}
	}
	if len(applyChanges) == 0 {
		for _, fc := range plan.Files {
			report.AlreadyApplied = append(report.AlreadyApplied, displayOrPath(fc))
		}

		return report, nil
	}

	shortID := strings.TrimPrefix(plan.ID, "plan-")
	if len(shortID) > 16 {
		shortID = shortID[:16]
	}
	txDir, err := os.MkdirTemp(stateDir, "tx-"+shortID+"-")
	if err != nil {
		return nil, &ApplyError{Code: CodeApplyFailed, Message: "cannot create transaction directory", Cause: err}
	}
	txID := filepath.Base(txDir)
	report.TransactionID = txID

	j := &Journal{ID: txID, PlanID: plan.ID, Status: "prepared", CreatedAt: time.Now().UTC()}
	for changeIndex, planIndex := range applyChanges {
		fc := plan.Files[planIndex]
		st := states[fc.Path]
		jf := JournalFile{
			Path:         fc.Path,
			DisplayPath:  displayOrPath(fc),
			BeforeSHA256: fc.BeforeSHA256,
			AfterSHA256:  fc.AfterSHA256,
			Mode:         fc.Mode,
			Delete:       fc.Delete,
			Existed:      st.exists,
		}
		if st.exists {
			jf.BackupName = fmt.Sprintf("backup-%03d.bin", changeIndex)
			if err := os.WriteFile(filepath.Join(txDir, jf.BackupName), st.b, 0o600); err != nil {
				_ = os.RemoveAll(txDir)

				return nil, &ApplyError{Code: CodeApplyFailed, Message: "cannot write recovery copy", Cause: err}
			}
		}
		if !fc.Delete {
			jf.NewName = fmt.Sprintf("new-%03d.bin", changeIndex)
			if err := os.WriteFile(filepath.Join(txDir, jf.NewName), fc.ProposedContent, 0o600); err != nil {
				_ = os.RemoveAll(txDir)

				return nil, &ApplyError{Code: CodeApplyFailed, Message: "cannot stage proposed content", Cause: err}
			}
		}
		j.Files = append(j.Files, jf)
	}
	if err := writeJournal(txDir, j); err != nil {
		_ = os.RemoveAll(txDir)

		return nil, &ApplyError{Code: CodeApplyFailed, Message: "cannot write transaction journal", Cause: err}
	}

	for i, jf := range j.Files {
		fc := plan.Files[applyChanges[i]]
		var applyErr error
		switch {
		case fc.Delete:
			applyErr = os.Remove(fc.Path)
			if errors.Is(applyErr, os.ErrNotExist) {
				applyErr = nil
			}
		default:
			mode := os.FileMode(fc.Mode)
			if mode == 0 {
				mode = 0o644
			}
			applyErr = atomicWrite(fc.Path, fc.ProposedContent, mode)
		}
		if applyErr != nil {
			if rbErr := rollbackJournal(txDir, j); rbErr != nil {
				_ = markRecoveryFailed(txDir, j, rbErr)

				return nil, &ApplyError{
					Code:      CodeRollbackFailed,
					Message:   "application failed and automatic rollback also failed",
					File:      jf.DisplayPath,
					BackupDir: txDir,
					Recovery:  fmt.Sprintf("inspect %s and restore backup-*.bin manually, then run: osv-scanner fix recover --state-dir %s", txDir, stateDir),
					Cause:     errors.Join(applyErr, rbErr),
				}
			}
			_ = os.RemoveAll(txDir)

			return nil, &ApplyError{
				Code:    CodeApplyFailed,
				Message: "application failed; all target files were restored to their pre-apply bytes",
				File:    jf.DisplayPath,
				Cause:   applyErr,
			}
		}
		report.Applied = append(report.Applied, jf.DisplayPath)
	}

	j.Status = "committed"
	_ = writeJournal(txDir, j)
	if err := os.RemoveAll(txDir); err != nil {
		// The file changes are complete and valid. Leave the journal for the
		// next recovery pass rather than reporting a failed application.
		report.Recovered = append(report.Recovered, txID)
	}

	return report, nil
}

// Recover finds and rolls back interrupted transactions.
func Recover(opts ApplyOptions) ([]string, error) {
	stateDir, err := resolveStateDir(opts.StateDir)
	if err != nil {
		return nil, &ApplyError{Code: CodeRecoveryRequired, Message: "cannot determine transaction state directory", Cause: err}
	}
	lock, err := acquireApplyLock(stateDir)
	if err != nil {
		return nil, err
	}
	defer lock.Release() //nolint:errcheck

	return recoverPendingLocked(stateDir)
}

func resolveStateDir(v string) (string, error) {
	if v != "" {
		return filepath.Abs(v)
	}

	return DefaultStateDir()
}

func validateTargets(plan *Plan) (map[string]currentState, []int, []Conflict, error) {
	states := make(map[string]currentState, len(plan.Files))
	var applyChanges []int
	var conflicts []Conflict

	for i, fc := range plan.Files {
		st, err := readCurrentState(fc.Path)
		if err != nil {
			return nil, nil, nil, &ApplyError{Code: CodeApplyFailed, Message: "cannot inspect target file", File: displayOrPath(fc), Cause: err}
		}
		states[fc.Path] = st

		switch st.hash {
		case fc.BeforeSHA256:
			applyChanges = append(applyChanges, i)
		case fc.AfterSHA256:
			// Already in intended state.
		default:
			reason := "current content does not match either generated or intended content"
			if !st.exists {
				reason = "target file is missing"
			}
			conflicts = append(conflicts, Conflict{
				Path:           fc.Path,
				DisplayPath:    displayOrPath(fc),
				Reason:         reason,
				ExpectedBefore: fc.BeforeSHA256,
				ExpectedAfter:  fc.AfterSHA256,
				ActualSHA256:   st.hash,
			})
		}
	}

	return states, applyChanges, conflicts, nil
}

func readCurrentState(path string) (currentState, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return currentState{exists: false, hash: ""}, nil
		}

		return currentState{}, err
	}
	info, statErr := os.Stat(path)
	var mode os.FileMode
	if statErr == nil {
		mode = info.Mode()
	}

	return currentState{b: b, exists: true, hash: HashBytes(b), mode: mode}, nil
}

func displayOrPath(fc FileChange) string {
	if fc.DisplayPath != "" {
		return fc.DisplayPath
	}

	return fc.Path
}

func writeJournal(txDir string, j *Journal) error {
	b, err := json.MarshalIndent(j, "", "  ")
	if err != nil {
		return err
	}

	return atomicWrite(filepath.Join(txDir, "journal.json"), b, 0o600)
}

func markRecoveryFailed(txDir string, j *Journal, cause error) error {
	j.Status = "recovery_failed"
	_ = writeJournal(txDir, j)
	if _, ok := errors.AsType[*ApplyError](cause); ok {
		return cause
	}

	return cause
}

func rollbackJournal(txDir string, j *Journal) error {
	// restoreJournal skips files whose current bytes already match the backup.
	// That is important when the failure happened while opening the next
	// read-only target's directory: that target was never changed and rolling
	// it back must not require directory write permission.
	return restoreJournal(txDir, j)
}

func recoverPendingLocked(stateDir string) ([]string, error) {
	entries, err := os.ReadDir(stateDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}

		return nil, &ApplyError{Code: CodeRecoveryRequired, Message: "cannot read transaction state directory", BackupDir: stateDir, Cause: err}
	}

	var recovered []string
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "tx-") {
			continue
		}
		txDir := filepath.Join(stateDir, entry.Name())
		j, err := loadJournal(txDir)
		if err != nil {
			return nil, &ApplyError{
				Code:      CodeRecoveryRequired,
				Message:   "found an unfinished transaction without a readable journal; refusing to guess file state",
				BackupDir: txDir,
				Recovery:  "inspect journal.json and backup-*.bin; restore files manually, then remove " + txDir,
				Cause:     err,
			}
		}
		if j.Status == "recovery_failed" {
			return nil, &ApplyError{
				Code:      CodeRecoveryRequired,
				Message:   "a previous rollback could not restore every file; manual recovery is still required",
				BackupDir: txDir,
				Recovery:  fmt.Sprintf("restore backup-*.bin to their target paths and remove %s, or fix permissions and run: osv-scanner fix recover --state-dir %s", txDir, stateDir),
			}
		}

		if err := restoreJournal(txDir, j); err != nil {
			_ = markRecoveryFailed(txDir, j, err)

			return nil, &ApplyError{
				Code:      CodeRecoveryRequired,
				Message:   "found an interrupted application but could not restore all target files",
				BackupDir: txDir,
				Recovery:  fmt.Sprintf("restore backup-*.bin manually, then remove %s; after fixing permissions run: osv-scanner fix recover --state-dir %s", txDir, stateDir),
				Cause:     err,
			}
		}
		cleanupStaleTemps(j)
		if err := os.RemoveAll(txDir); err != nil {
			return nil, &ApplyError{Code: CodeRecoveryRequired, Message: "files were restored but transaction cleanup failed", BackupDir: txDir, Cause: err}
		}
		recovered = append(recovered, j.ID)
	}
	slices.Sort(recovered)

	return recovered, nil
}

func loadJournal(txDir string) (*Journal, error) {
	b, err := os.ReadFile(filepath.Join(txDir, "journal.json"))
	if err != nil {
		return nil, err
	}
	var j Journal
	if err := json.Unmarshal(b, &j); err != nil {
		return nil, err
	}
	if j.ID == "" || len(j.Files) == 0 {
		return nil, errors.New("journal is incomplete")
	}

	return &j, nil
}

func restoreJournal(txDir string, j *Journal) error {
	var errs []error
	for _, jf := range j.Files {
		if !jf.Existed {
			if err := os.Remove(jf.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, err)
			}

			continue
		}
		b, err := os.ReadFile(filepath.Join(txDir, jf.BackupName))
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if HashBytes(b) != jf.BeforeSHA256 {
			errs = append(errs, fmt.Errorf("backup hash mismatch for %s", jf.DisplayPath))
			continue
		}
		if current, err := os.ReadFile(jf.Path); err == nil && HashBytes(current) == jf.BeforeSHA256 {
			continue
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
			continue
		}
		mode := os.FileMode(jf.Mode)
		if mode == 0 {
			mode = 0o644
		}
		if err := atomicWrite(jf.Path, b, mode); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func cleanupStaleTemps(j *Journal) {
	dirs := map[string]struct{}{}
	for _, jf := range j.Files {
		dirs[filepath.Dir(jf.Path)] = struct{}{}
	}
	for dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, ".osv-scanner-fix-*"))
		if err != nil {
			continue
		}
		for _, m := range matches {
			_ = os.Remove(m)
		}
	}
}
