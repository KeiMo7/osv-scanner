package fixplan

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"deps.dev/util/resolve"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ResolveSource is one ordered dependency-data source.
type ResolveSource struct {
	Name   string
	Client resolve.Client
}

// Router is a priority-ordered, per-package pinned resolve.Client.
//
// A package is pinned to the first source that returns usable version graph
// data. Later calls for that package never combine responses from another
// source. Before a package is pinned, explicit not-found/empty-version
// responses and source availability failures move to the next source.
type Router struct {
	sources []ResolveSource

	mu       sync.Mutex
	pins     map[string]string
	prov     map[string]*DependencyProvenance
	reports  map[string]*SourceReport
	disabled map[string]string
}

// NewRouter creates a router. Source order is priority order.
func NewRouter(sources []ResolveSource) (*Router, error) {
	if len(sources) == 0 {
		return nil, errors.New("at least one data source is required")
	}
	r := &Router{
		sources:  append([]ResolveSource(nil), sources...),
		pins:     make(map[string]string),
		prov:     make(map[string]*DependencyProvenance),
		reports:  make(map[string]*SourceReport),
		disabled: make(map[string]string),
	}
	for i, s := range r.sources {
		if s.Name == "" || s.Client == nil {
			return nil, fmt.Errorf("source at priority %d has no name or client", i)
		}
		if _, exists := r.reports[s.Name]; exists {
			return nil, fmt.Errorf("duplicate data source %q", s.Name)
		}
		r.reports[s.Name] = &SourceReport{Name: s.Name, Priority: i, Status: "untried"}
	}

	return r, nil
}

// Sources returns the ordered source names.
func (r *Router) Sources() []string {
	names := make([]string, len(r.sources))
	for i, s := range r.sources {
		names[i] = s.Name
	}

	return names
}

// Disable marks a source unavailable for subsequent complete replans.
func (r *Router) Disable(name, reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.disabled[name] = reason
	if rep := r.reports[name]; rep != nil {
		rep.Status = "unavailable"
		rep.Code = CodeSourceUnavailable
		if rep.Message == "" {
			rep.Message = "source unavailable"
		}
	}
}

// IsDisabled reports whether Disable was called for name.
func (r *Router) IsDisabled(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.disabled[name]

	return ok
}

// Provenance returns sorted per-dependency source records.
func (r *Router) Provenance() []DependencyProvenance {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]DependencyProvenance, 0, len(r.prov))
	for _, p := range r.prov {
		cp := *p
		cp.Attempts = append([]SourceAttempt(nil), p.Attempts...)
		out = append(out, cp)
	}

	return out
}

// Reports returns sorted non-secret source status reports.
func (r *Router) Reports() []SourceReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]SourceReport, 0, len(r.reports))
	for _, s := range r.sources {
		if rep, ok := r.reports[s.Name]; ok {
			out = append(out, *rep)
		}
	}

	return out
}

func packageKey(k resolve.PackageKey) string {
	return k.String()
}

func (r *Router) sourceByName(name string) (ResolveSource, int, bool) {
	for i, s := range r.sources {
		if s.Name == name {
			return s, i, true
		}
	}

	return ResolveSource{}, -1, false
}

func (r *Router) pinnedSource(key string) (ResolveSource, bool) {
	r.mu.Lock()
	name, ok := r.pins[key]
	r.mu.Unlock()
	if !ok {
		return ResolveSource{}, false
	}
	s, _, exists := r.sourceByName(name)
	if !exists {
		return ResolveSource{Name: name}, true
	}

	return s, true
}

func (r *Router) pinnedCallError(key string, src ResolveSource, requested string) error {
	if r.IsDisabled(src.Name) {
		err := fmt.Errorf("%w: %s", ErrSourceUnavailable, src.Name)
		r.classifyPinnedError(key, src.Name, requested, err)

		return wrapPinnedError(src.Name, key, err)
	}

	return nil
}

func (r *Router) recordAttempt(key, ecosystem, name, requested string, priority int, outcome, code, message string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.prov[key]
	if !ok {
		p = &DependencyProvenance{Key: key, Ecosystem: ecosystem, Name: keyName(key), RequestedVersion: requested}
		r.prov[key] = p
	}
	if requested != "" && p.RequestedVersion == "" {
		p.RequestedVersion = requested
	}
	p.Attempts = append(p.Attempts, SourceAttempt{
		Source:   name,
		Priority: priority,
		Outcome:  outcome,
		Code:     code,
		Message:  RedactText(message),
	})
	if rep := r.reports[name]; rep != nil {
		switch outcome {
		case OutcomeHit:
			rep.Status = "available"
			rep.Code = ""
			rep.Message = ""
		case OutcomeUnavailable:
			rep.Status = "unavailable"
			rep.Code = CodeSourceUnavailable
			if rep.Message == "" {
				rep.Message = "source unavailable"
			}
		case OutcomeNotFound, OutcomeNoVersion:
			if rep.Status != "unavailable" {
				rep.Status = "available"
			}
		}
	}
}

func keyName(key string) string {
	if _, name, ok := strings.Cut(key, ":"); ok {
		return name
	}

	return key
}

func (r *Router) selectSource(
	ctx context.Context,
	key, ecosystem, requested string,
	call func(resolve.Client) error,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	var attempts []SourceAttempt
	sawDefinitiveMissing := false
	for priority, src := range r.sources {
		r.mu.Lock()
		_, disabled := r.disabled[src.Name]
		r.mu.Unlock()
		if disabled {
			attempts = append(attempts, SourceAttempt{Source: src.Name, Priority: priority, Outcome: OutcomeUnavailable, Code: CodeSourceUnavailable, Message: "source disabled after an earlier failure"})
			continue
		}

		err := call(src.Client)
		if err == nil {
			r.mu.Lock()
			r.pins[key] = src.Name
			p := r.prov[key]
			if p == nil {
				p = &DependencyProvenance{Key: key, Ecosystem: ecosystem, Name: keyName(key), RequestedVersion: requested}
				r.prov[key] = p
			}
			p.SelectedSource = src.Name
			if len(p.Attempts) == 0 {
				p.SelectionReason = "highest_priority_available"
			} else {
				last := p.Attempts[len(p.Attempts)-1]
				switch last.Outcome {
				case OutcomeNotFound:
					p.SelectionReason = "fallback_after_not_found"
				case OutcomeNoVersion:
					p.SelectionReason = "fallback_after_no_available_version"
				case OutcomeUnavailable:
					p.SelectionReason = "fallback_after_source_unavailable"
				default:
					p.SelectionReason = "fallback"
				}
			}
			r.mu.Unlock()
			r.recordAttempt(key, ecosystem, src.Name, requested, priority, OutcomeHit, "", "")

			return nil
		}

		kind, code := classifyFailure(err)
		outcome := string(kind)
		if outcome == "" {
			outcome = "error"
		}
		safe := safeFailureMessage(kind)
		r.recordAttempt(key, ecosystem, src.Name, requested, priority, outcome, code, safe)
		attempts = append(attempts, SourceAttempt{Source: src.Name, Priority: priority, Outcome: outcome, Code: code, Message: safe})
		if kind == FailureNotFound || kind == FailureNoVersion {
			sawDefinitiveMissing = true
		}
		if kind == FailureUnavailable {
			r.Disable(src.Name, code)
		}
	}

	code := CodeAllSourcesUnavailable
	if sawDefinitiveMissing {
		code = CodeNoAvailableVersion
	}

	return &SourceSelectionError{Code: code, Attempts: attempts}
}

// Version implements resolve.Client.
func (r *Router) Version(ctx context.Context, vk resolve.VersionKey) (resolve.Version, error) {
	key := packageKey(vk.PackageKey)
	if src, ok := r.pinnedSource(key); ok {
		if err := r.pinnedCallError(key, src, vk.Version); err != nil {
			return resolve.Version{}, err
		}
		v, err := src.Client.Version(ctx, vk)
		if err != nil {
			r.classifyPinnedError(key, src.Name, vk.Version, err)
		}

		return v, wrapPinnedError(src.Name, key, err)
	}

	var result resolve.Version
	err := r.selectSource(ctx, key, vk.System.String(), vk.Version, func(c resolve.Client) error {
		v, err := c.Version(ctx, vk)
		if err != nil {
			return err
		}
		result = v

		return nil
	})

	return result, err
}

// Versions implements resolve.Client.
func (r *Router) Versions(ctx context.Context, pk resolve.PackageKey) ([]resolve.Version, error) {
	key := packageKey(pk)
	if src, ok := r.pinnedSource(key); ok {
		if err := r.pinnedCallError(key, src, ""); err != nil {
			return nil, err
		}
		vs, err := src.Client.Versions(ctx, pk)
		if err != nil {
			r.classifyPinnedError(key, src.Name, "", err)
		}

		return vs, wrapPinnedError(src.Name, key, err)
	}

	var result []resolve.Version
	err := r.selectSource(ctx, key, pk.System.String(), "", func(c resolve.Client) error {
		vs, err := c.Versions(ctx, pk)
		if err != nil {
			return err
		}
		if len(vs) == 0 {
			return ErrNoAvailableVersion
		}
		result = vs

		return nil
	})

	return result, err
}

// Requirements implements resolve.Client.
func (r *Router) Requirements(ctx context.Context, vk resolve.VersionKey) ([]resolve.RequirementVersion, error) {
	key := packageKey(vk.PackageKey)
	if src, ok := r.pinnedSource(key); ok {
		if err := r.pinnedCallError(key, src, vk.Version); err != nil {
			return nil, err
		}
		reqs, err := src.Client.Requirements(ctx, vk)
		if err != nil {
			r.classifyPinnedError(key, src.Name, vk.Version, err)
		}

		return reqs, wrapPinnedError(src.Name, key, err)
	}

	var result []resolve.RequirementVersion
	err := r.selectSource(ctx, key, vk.System.String(), vk.Version, func(c resolve.Client) error {
		reqs, err := c.Requirements(ctx, vk)
		if err != nil {
			return err
		}
		result = reqs

		return nil
	})

	return result, err
}

// MatchingVersions implements resolve.Client.
func (r *Router) MatchingVersions(ctx context.Context, vk resolve.VersionKey) ([]resolve.Version, error) {
	key := packageKey(vk.PackageKey)
	if src, ok := r.pinnedSource(key); ok {
		if err := r.pinnedCallError(key, src, vk.Version); err != nil {
			return nil, err
		}
		vs, err := src.Client.MatchingVersions(ctx, vk)
		if err != nil {
			r.classifyPinnedError(key, src.Name, vk.Version, err)
		}

		return vs, wrapPinnedError(src.Name, key, err)
	}

	var result []resolve.Version
	err := r.selectSource(ctx, key, vk.System.String(), vk.Version, func(c resolve.Client) error {
		vs, err := c.MatchingVersions(ctx, vk)
		if err != nil {
			return err
		}
		if len(vs) == 0 {
			return ErrNoAvailableVersion
		}
		result = vs

		return nil
	})

	return result, err
}

func (r *Router) classifyPinnedError(key, source, requested string, err error) {
	if err == nil {
		return
	}
	kind, code := classifyFailure(err)
	r.recordAttempt(key, "", source, requested, -1, string(kind), code, safeFailureMessage(kind))
	if kind == FailureUnavailable {
		r.Disable(source, code)
	}
}

func wrapPinnedError(source, key string, err error) error {
	if err == nil {
		return nil
	}
	kind, code := classifyFailure(err)

	return &PinnedSourceError{Source: source, Key: key, Kind: kind, Code: code, Cause: err}
}

// FailureKind classifies a source response.
type FailureKind string

const (
	FailureNotFound    FailureKind = OutcomeNotFound
	FailureNoVersion   FailureKind = OutcomeNoVersion
	FailureUnavailable FailureKind = OutcomeUnavailable
	FailureInvalid     FailureKind = "invalid_response"
	FailureOther       FailureKind = "error"
)

// Stable error codes used in CLI/JSON output.
const (
	CodeSourceUnavailable     = "SOURCE_UNAVAILABLE"
	CodeNoAvailableVersion    = "NO_AVAILABLE_VERSION"
	CodeAllSourcesUnavailable = "ALL_SOURCES_UNAVAILABLE"
	CodeConflict              = "PLAN_CONFLICT"
	CodeApplyFailed           = "APPLY_FAILED"
	CodeRollbackFailed        = "ROLLBACK_FAILED"
	CodeRecoveryRequired      = "RECOVERY_REQUIRED"
	CodeLocked                = "APPLY_LOCKED"
)

// Sentinel source errors useful in tests and source implementations.
var (
	ErrSourceUnavailable  = errors.New("source unavailable")
	ErrNoAvailableVersion = errors.New("no available version")
)

// SourceSelectionError says no ordered source could provide a package.
type SourceSelectionError struct {
	Code     string
	Attempts []SourceAttempt
	cause    error
}

func (e *SourceSelectionError) Error() string {
	if e.Code == CodeNoAvailableVersion {
		return "no data source could provide a matching version"
	}

	return "all data sources are unavailable"
}

func (e *SourceSelectionError) Unwrap() error { return e.cause }

// PinnedSourceError prevents silently mixing version graphs for one package.
type PinnedSourceError struct {
	Source string
	Key    string
	Kind   FailureKind
	Code   string
	Cause  error
}

func (e *PinnedSourceError) Error() string {
	if e.Kind == FailureUnavailable {
		return fmt.Sprintf("pinned data source %q became unavailable for %s; replan required", e.Source, e.Key)
	}

	return fmt.Sprintf("data source %q could not complete the version graph for %s", e.Source, e.Key)
}

func (e *PinnedSourceError) Unwrap() error { return e.Cause }

func classifyFailure(err error) (FailureKind, string) {
	if err == nil {
		return "", ""
	}
	if errors.Is(err, context.Canceled) {
		return FailureOther, "CANCELED"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrSourceUnavailable) {
		return FailureUnavailable, CodeSourceUnavailable
	}
	if errors.Is(err, ErrNoAvailableVersion) {
		return FailureNoVersion, CodeNoAvailableVersion
	}
	if errors.Is(err, resolve.ErrNotFound) {
		return FailureNotFound, "NOT_FOUND"
	}
	if errors.Is(err, ErrSourceUnavailable) {
		return FailureUnavailable, CodeSourceUnavailable
	}

	if st, ok := status.FromError(err); ok {
		switch st.Code() {
		case codes.NotFound:
			return FailureNotFound, "NOT_FOUND"
		case codes.DeadlineExceeded, codes.Unavailable, codes.ResourceExhausted:
			return FailureUnavailable, CodeSourceUnavailable
		case codes.InvalidArgument, codes.FailedPrecondition:
			return FailureInvalid, "INVALID_RESPONSE"
		default:
			// Other gRPC codes fall through to generic classification.
		}
	}

	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found") || strings.Contains(msg, "404"):
		return FailureNotFound, "NOT_FOUND"
	case strings.Contains(msg, "no available version") || strings.Contains(msg, "no versions"):
		return FailureNoVersion, CodeNoAvailableVersion
	case strings.Contains(msg, "connection refused"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "bad gateway"),
		strings.Contains(msg, "service unavailable"),
		strings.Contains(msg, "gateway timeout"),
		strings.Contains(msg, "tls handshake timeout"),
		strings.Contains(msg, "eof"):
		return FailureUnavailable, CodeSourceUnavailable
	}

	return FailureOther, "SOURCE_ERROR"
}

func safeFailureMessage(kind FailureKind) string {
	switch kind {
	case FailureNotFound:
		return "package or version not found"
	case FailureNoVersion:
		return "no matching version"
	case FailureUnavailable:
		return "source unavailable"
	case FailureInvalid:
		return "invalid source response"
	default:
		return "source request failed"
	}
}
