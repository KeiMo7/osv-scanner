package fixplan

import (
	"errors"
	"fmt"
	"strings"
)

// ErrLocked is returned by platform lock implementations when a nonblocking
// lock is already held.
var ErrLocked = errors.New("lock already held")

// ApplyError is a user-safe application/recovery error.
type ApplyError struct {
	Code      string
	Message   string
	File      string
	BackupDir string
	Recovery  string
	Conflicts []Conflict
	Recovered []string
	Cause     error
}

// Conflict describes one target whose current bytes do not match the plan.
type Conflict struct {
	Path           string `json:"path"`
	DisplayPath    string `json:"display_path,omitempty"`
	Reason         string `json:"reason"`
	ExpectedBefore string `json:"expected_before_sha256,omitempty"`
	ExpectedAfter  string `json:"expected_after_sha256,omitempty"`
	ActualSHA256   string `json:"actual_sha256,omitempty"`
}

func (e *ApplyError) Error() string {
	var b strings.Builder
	b.WriteString(e.Message)
	if e.File != "" {
		fmt.Fprintf(&b, ": %s", e.File)
	}
	if len(e.Conflicts) > 0 {
		for _, c := range e.Conflicts {
			fmt.Fprintf(&b, "\n  - %s: %s", c.DisplayPathOrPath(), c.Reason)
		}
	}
	if e.BackupDir != "" {
		fmt.Fprintf(&b, "\nRecoverable copies are in: %s", e.BackupDir)
	}
	if e.Recovery != "" {
		fmt.Fprintf(&b, "\nRecovery: %s", e.Recovery)
	}

	return b.String()
}

// Unwrap exposes the underlying error for errors.Is/As without printing raw
// filesystem or network details to end users.
func (e *ApplyError) Unwrap() error { return e.Cause }

// DisplayPathOrPath returns the best path for a conflict.
func (c Conflict) DisplayPathOrPath() string {
	if c.DisplayPath != "" {
		return c.DisplayPath
	}

	return c.Path
}

// IsRecoveryRequired reports whether err contains a manual recovery location.
func IsRecoveryRequired(err error) bool {
	if ae, ok := errors.AsType[*ApplyError](err); ok {
		return ae.Code == CodeRecoveryRequired
	}

	return false
}

// IsConflict reports whether err is a plan/file conflict rejection.
func IsConflict(err error) bool {
	if ae, ok := errors.AsType[*ApplyError](err); ok {
		return ae.Code == CodeConflict
	}

	return false
}
