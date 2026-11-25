// Package fixplan contains the reviewable plan, comparison, and recoverable
// transaction primitives used by the osv-scanner fix workflow.
//
// The package is intentionally independent from the CLI and from the
// guidedremediation result type so that plans can be generated, reviewed,
// compared, and applied deterministically.
package fixplan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// APIVersion is the current plan schema version.
const APIVersion = "osv-scanner/fixplan-v1"

// SHA256Prefix prefixes every content hash stored in a plan or journal.
const SHA256Prefix = "sha256:"

// Plan is a deterministic, reviewable set of file changes.
type Plan struct {
	// APIVersion identifies the plan schema.
	APIVersion string `json:"api_version"`
	// ID is the content-derived identifier for the plan.
	ID string `json:"id"`

	// Sources describes the ordered data sources used to build the plan.
	Sources []SourceReport `json:"sources,omitempty"`
	// Dependencies records the source selected for individual dependencies.
	Dependencies []DependencyProvenance `json:"dependencies,omitempty"`
	// Upgrades is the deterministic target-version view of result patches.
	Upgrades []Upgrade `json:"upgrades,omitempty"`
	// Vulnerabilities is a compact, comparison-friendly vulnerability view.
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	// FixedVulnerabilityIDs are the IDs fixed by this plan's selected patches.
	FixedVulnerabilityIDs []string `json:"fixed_vulnerability_ids,omitempty"`

	// Files are the target file changes, sorted by path.
	Files []FileChange `json:"files"`
}

// Upgrade is one dependency target version change.
type Upgrade struct {
	Name        string `json:"name"`
	VersionFrom string `json:"version_from,omitempty"`
	VersionTo   string `json:"version_to"`
	Ecosystem   string `json:"ecosystem,omitempty"`
}

// Vulnerability is the compact plan-level vulnerability record.
type Vulnerability struct {
	ID           string `json:"id"`
	Unactionable bool   `json:"unactionable,omitempty"`
}

// FileChange is one target file's before/after state.
type FileChange struct {
	// Path is the absolute, cleaned target path.
	Path string `json:"path"`
	// DisplayPath is the path shown to users and used in unified diff headers.
	DisplayPath string `json:"display_path"`

	// BeforeSHA256 is the hash of the file when the plan was generated.
	BeforeSHA256 string `json:"before_sha256"`
	// AfterSHA256 is the hash of ProposedContent, or empty for a deletion.
	AfterSHA256 string `json:"after_sha256,omitempty"`

	// Mode is the regular file mode bits.
	Mode uint32 `json:"mode"`
	// Delete reports that Path should be deleted.
	Delete bool `json:"delete,omitempty"`

	// ProposedContentBase64 is the complete intended post-apply content.
	ProposedContent []byte `json:"proposed_content_base64,omitempty"`
	// UnifiedDiff is a human-readable review diff. It is derived data and does
	// not participate in plan identity.
	UnifiedDiff string `json:"unified_diff,omitempty"`
}

// SourceReport is the non-secret status of one configured source.
type SourceReport struct {
	Name     string `json:"name"`
	Priority int    `json:"priority"`
	Status   string `json:"status"`
	// Code is a stable machine-readable status/error code.
	Code string `json:"code,omitempty"`
	// Message is a credential-free, user-safe explanation.
	Message string `json:"message,omitempty"`
}

// Source attempt outcomes.
const (
	OutcomeHit         = "hit"
	OutcomeNotFound    = "not_found"
	OutcomeNoVersion   = "no_available_version"
	OutcomeUnavailable = "source_unavailable"
	OutcomeInvalid     = "invalid_response"
)

// DependencyProvenance records where one dependency's version graph came from.
type DependencyProvenance struct {
	Key              string          `json:"key"`
	Ecosystem        string          `json:"ecosystem,omitempty"`
	Name             string          `json:"name"`
	RequestedVersion string          `json:"requested_version,omitempty"`
	SelectedSource   string          `json:"selected_source,omitempty"`
	SelectionReason  string          `json:"selection_reason,omitempty"`
	Attempts         []SourceAttempt `json:"attempts,omitempty"`
}

// SourceAttempt records one ordered source lookup while selecting a source.
type SourceAttempt struct {
	Source   string `json:"source"`
	Priority int    `json:"priority"`
	Outcome  string `json:"outcome"`
	Code     string `json:"code,omitempty"`
	Message  string `json:"message,omitempty"`
}

// HashBytes returns the canonical hash representation for b.
func HashBytes(b []byte) string {
	sum := sha256.Sum256(b)

	return SHA256Prefix + hex.EncodeToString(sum[:])
}

// HashFile returns the canonical hash representation for a file.
func HashFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}

	return HashBytes(b), nil
}

// SnapshotFile reads a file and returns its bytes, mode, and hash.
func SnapshotFile(path string) ([]byte, os.FileMode, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, 0, "", err
	}
	if !info.Mode().IsRegular() {
		return nil, 0, "", fmt.Errorf("%s is not a regular file", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, "", err
	}

	return b, info.Mode().Perm(), HashBytes(b), nil
}

// NewFileChange creates a change from a known before state and proposed bytes.
func NewFileChange(path, displayPath string, before []byte, mode os.FileMode, proposed []byte) (FileChange, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return FileChange{}, err
	}
	abs = filepath.Clean(abs)
	if displayPath == "" {
		displayPath = path
	}

	fc := FileChange{
		Path:         abs,
		DisplayPath:  displayPath,
		BeforeSHA256: HashBytes(before),
		Mode:         uint32(mode.Perm()),
	}
	if proposed == nil {
		fc.Delete = true
	} else {
		proposed = slices.Clone(proposed)
		fc.ProposedContent = proposed
		fc.AfterSHA256 = HashBytes(proposed)
	}
	fc.UnifiedDiff = UnifiedDiff(displayPath, before, proposed)

	return fc, nil
}

// NewPlan validates changes, sorts them, and assigns a deterministic ID.
func NewPlan(changes []FileChange, sources []SourceReport, deps []DependencyProvenance) (*Plan, error) {
	files := slices.Clone(changes)
	slices.SortFunc(files, func(a, b FileChange) int { return strings.Compare(a.Path, b.Path) })

	seen := make(map[string]struct{}, len(files))
	for i := range files {
		fc := &files[i]
		if fc.Path == "" {
			return nil, errors.New("plan file change has empty path")
		}
		if _, ok := seen[fc.Path]; ok {
			return nil, fmt.Errorf("plan contains duplicate target %s", fc.Path)
		}
		seen[fc.Path] = struct{}{}

		if !strings.HasPrefix(fc.BeforeSHA256, SHA256Prefix) {
			return nil, fmt.Errorf("plan target %s is missing before hash", fc.DisplayPath)
		}
		if fc.Delete {
			if len(fc.ProposedContent) != 0 || fc.AfterSHA256 != "" {
				return nil, fmt.Errorf("deletion for %s must not contain proposed content", fc.DisplayPath)
			}
		} else {
			if fc.AfterSHA256 != HashBytes(fc.ProposedContent) {
				return nil, fmt.Errorf("after hash mismatch for %s", fc.DisplayPath)
			}
		}
	}

	sourceReports := slices.Clone(sources)
	slices.SortFunc(sourceReports, func(a, b SourceReport) int { return a.Priority - b.Priority })
	depReports := slices.Clone(deps)
	slices.SortFunc(depReports, func(a, b DependencyProvenance) int {
		if c := strings.Compare(a.Key, b.Key); c != 0 {
			return c
		}

		return strings.Compare(a.Name, b.Name)
	})

	p := &Plan{
		APIVersion:   APIVersion,
		Sources:      sourceReports,
		Dependencies: depReports,
		Files:        files,
	}
	p.ID = p.computeID()

	return p, nil
}

type planIdentity struct {
	APIVersion            string                 `json:"api_version"`
	Sources               []SourceReport         `json:"sources,omitempty"`
	Dependencies          []DependencyProvenance `json:"dependencies,omitempty"`
	Upgrades              []Upgrade              `json:"upgrades,omitempty"`
	Vulnerabilities       []Vulnerability        `json:"vulnerabilities,omitempty"`
	FixedVulnerabilityIDs []string               `json:"fixed_vulnerability_ids,omitempty"`
	Files                 []fileChangeIdentity   `json:"files"`
}

type fileChangeIdentity struct {
	Path         string `json:"path"`
	BeforeSHA256 string `json:"before_sha256"`
	AfterSHA256  string `json:"after_sha256,omitempty"`
	Mode         uint32 `json:"mode"`
	Delete       bool   `json:"delete,omitempty"`
	Content      []byte `json:"proposed_content_base64,omitempty"`
}

func (p *Plan) computeID() string {
	id := planIdentity{
		APIVersion:            p.APIVersion,
		Sources:               p.Sources,
		Dependencies:          p.Dependencies,
		Upgrades:              p.Upgrades,
		Vulnerabilities:       p.Vulnerabilities,
		FixedVulnerabilityIDs: p.FixedVulnerabilityIDs,
	}
	for _, f := range p.Files {
		id.Files = append(id.Files, fileChangeIdentity{
			Path:         f.Path,
			BeforeSHA256: f.BeforeSHA256,
			AfterSHA256:  f.AfterSHA256,
			Mode:         f.Mode,
			Delete:       f.Delete,
			Content:      f.ProposedContent,
		})
	}
	b, err := json.Marshal(id)
	if err != nil {
		panic(fmt.Sprintf("fixplan: cannot marshal content-derived identity: %v", err))
	}

	return "plan-" + HashBytes(b)[len(SHA256Prefix):][:16]
}

// RecomputeID recalculates and assigns the content-derived plan ID.
func RecomputeID(p *Plan) string {
	p.ID = p.computeID()

	return p.ID
}

// Validate checks the plan structure and content hashes.
func (p *Plan) Validate() error {
	if p == nil {
		return errors.New("nil plan")
	}
	if p.APIVersion != APIVersion {
		return fmt.Errorf("unsupported plan api_version %q", p.APIVersion)
	}
	if len(p.Files) == 0 {
		return nil
	}
	prev := ""
	for _, f := range p.Files {
		if f.Path == "" {
			return errors.New("plan contains a file change with no path")
		}
		if f.Path < prev {
			return errors.New("plan file changes are not sorted by path")
		}
		prev = f.Path
		if !strings.HasPrefix(f.BeforeSHA256, SHA256Prefix) {
			return fmt.Errorf("plan target %s has invalid before hash", f.DisplayPath)
		}
		if f.Delete {
			if f.AfterSHA256 != "" || len(f.ProposedContent) != 0 {
				return fmt.Errorf("plan deletion %s contains proposed content", f.DisplayPath)
			}

			continue
		}
		if f.AfterSHA256 != HashBytes(f.ProposedContent) {
			return fmt.Errorf("plan target %s has inconsistent proposed content", f.DisplayPath)
		}
	}
	expectedID := p.computeID()
	if p.ID != "" && p.ID != expectedID {
		return fmt.Errorf("plan id %q does not match content-derived id %q", p.ID, expectedID)
	}

	return nil
}

// LoadPlan reads and validates a plan JSON document.
func LoadPlan(r io.Reader) (*Plan, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var p Plan
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}

	return &p, nil
}

// LoadPlanFile opens, reads, and validates a plan file.
func LoadPlanFile(path string) (*Plan, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return LoadPlan(f)
}

// WritePlanFile atomically writes the plan as indented JSON.
func WritePlanFile(path string, p *Plan) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	return atomicWrite(path, b, 0o600)
}

// WriteTextDiffs writes all per-file unified diffs to w.
func (p *Plan) WriteTextDiffs(w io.Writer) error {
	for _, f := range p.Files {
		if f.UnifiedDiff == "" {
			continue
		}
		if _, err := io.WriteString(w, f.UnifiedDiff); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}

	return nil
}
