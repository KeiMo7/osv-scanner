package fix

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/cmdlogger"
	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func applyPlanCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "apply",
		Usage:     "apply a reviewed plan transactionally",
		ArgsUsage: "[plan.json]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "plan", Aliases: []string{"p"}, Usage: "path to the plan JSON file", TakesFile: true},
			&cli.StringFlag{Name: "state-dir", Usage: "transaction state directory"},
			&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Value: "text", Usage: "output format: text, json"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			planPath := cmd.String("plan")
			if planPath == "" {
				planPath = cmd.Args().First()
			}
			if planPath == "" {
				return errors.New("plan file is required: osv-scanner fix apply --plan plan.json")
			}

			plan, err := fixplan.LoadPlanFile(planPath)
			if err != nil {
				applyErr := &fixplan.ApplyError{Code: "INVALID_PLAN", Message: "cannot read or validate plan file: " + planPath, Cause: err}
				if cmd.String("format") == "json" {
					_ = outputApplyJSON(stdout, nil, applyErr)
				}

				return redactError(applyErr)
			}

			report, err := fixplan.ApplyPlan(plan, fixplan.ApplyOptions{StateDir: cmd.String("state-dir")})
			if cmd.String("format") == "json" {
				if jsonErr := outputApplyJSON(stdout, report, err); jsonErr != nil {
					return jsonErr
				}
			} else if err == nil {
				writeApplyText(stdout, report)
			}

			if err != nil {
				var ae *fixplan.ApplyError
				if errors.As(err, &ae) && ae.Code == fixplan.CodeConflict {
					for _, c := range ae.Conflicts {
						cmdlogger.Errorf("conflict: %s: %s", c.DisplayPathOrPath(), c.Reason)
					}
				}

				return redactError(err)
			}

			return nil
		},
	}
}

func writeApplyText(w io.Writer, r *fixplan.ApplyReport) {
	for _, id := range r.Recovered {
		fmt.Fprintf(w, "RECOVERED-TRANSACTION: %s\n", id)
	}
	for _, p := range r.Applied {
		fmt.Fprintf(w, "APPLIED: %s\n", p)
	}
	for _, p := range r.AlreadyApplied {
		fmt.Fprintf(w, "ALREADY-APPLIED: %s\n", p)
	}
	fmt.Fprintf(w, "APPLY-OK: %s\n", r.PlanID)
}
