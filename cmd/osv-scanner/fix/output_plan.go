package fix

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scanner/v2/internal/fixplan"
)

type planJSONOutput struct {
	result.Result

	APIVersion            string                         `json:"api_version"`
	PlanID                string                         `json:"plan_id"`
	DryRun                bool                           `json:"dry_run"`
	Sources               []fixplan.SourceReport         `json:"sources,omitempty"`
	DependencySources     []fixplan.DependencyProvenance `json:"dependency_sources,omitempty"`
	Upgrades              []fixplan.Upgrade              `json:"planned_upgrades,omitempty"`
	FixedVulnerabilityIDs []string                       `json:"fixed_vulnerability_ids,omitempty"`
	Files                 []fixplan.FileChange           `json:"plan_files,omitempty"`
}

func outputPlanJSON(w io.Writer, res result.Result, plan *fixplan.Plan) error {
	out := planJSONOutput{
		Result:                res,
		APIVersion:            plan.APIVersion,
		PlanID:                plan.ID,
		DryRun:                true,
		Sources:               plan.Sources,
		DependencySources:     plan.Dependencies,
		Upgrades:              plan.Upgrades,
		FixedVulnerabilityIDs: plan.FixedVulnerabilityIDs,
		Files:                 plan.Files,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

type applyJSONOutput struct {
	OK     bool                 `json:"ok"`
	Report *fixplan.ApplyReport `json:"report,omitempty"`
	Error  *safeCLIError        `json:"error,omitempty"`
}

type safeCLIError struct {
	Code      string             `json:"code"`
	Message   string             `json:"message"`
	File      string             `json:"file,omitempty"`
	BackupDir string             `json:"backup_dir,omitempty"`
	Recovery  string             `json:"recovery,omitempty"`
	Conflicts []fixplan.Conflict `json:"conflicts,omitempty"`
}

func outputApplyJSON(w io.Writer, report *fixplan.ApplyReport, applyErr error) error {
	out := applyJSONOutput{OK: applyErr == nil, Report: report}
	if applyErr != nil {
		out.Error = safeError(applyErr)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(out)
}

func safeError(err error) *safeCLIError {
	if err == nil {
		return nil
	}
	se := &safeCLIError{Message: fixplan.RedactText(err.Error())}
	if ae, ok := errors.AsType[*fixplan.ApplyError](err); ok {
		se.Code = ae.Code
		se.Message = ae.Message
		se.File = ae.File
		se.BackupDir = ae.BackupDir
		se.Recovery = ae.Recovery
		se.Conflicts = ae.Conflicts
	}
	if sel, ok := errors.AsType[*fixplan.SourceSelectionError](err); ok {
		se.Code = sel.Code
		se.Message = sel.Error()
	}

	return se
}
