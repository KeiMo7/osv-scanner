package fix

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func comparePlansCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:      "compare",
		Usage:     "compare two generated fix plans",
		ArgsUsage: "<plan-a.json> <plan-b.json>",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "plan-a", Usage: "first plan JSON file"},
			&cli.StringFlag{Name: "plan-b", Usage: "second plan JSON file"},
			&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Value: "text", Usage: "output format: text, json"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			aPath := cmd.String("plan-a")
			bPath := cmd.String("plan-b")
			args := cmd.Args().Slice()
			if aPath == "" && len(args) > 0 {
				aPath = args[0]
			}
			if bPath == "" && len(args) > 1 {
				bPath = args[1]
			}
			if aPath == "" || bPath == "" {
				return errors.New("compare requires two plan files")
			}

			a, err := fixplan.LoadPlanFile(aPath)
			if err != nil {
				return redactError(fmt.Errorf("cannot load first plan: %w", err))
			}
			b, err := fixplan.LoadPlanFile(bPath)
			if err != nil {
				return redactError(fmt.Errorf("cannot load second plan: %w", err))
			}
			cmp := fixplan.ComparePlans(a, b)
			if cmd.String("format") == "json" {
				return redactError(cmp.WriteJSON(stdout))
			}

			return redactError(cmp.WriteText(stdout))
		},
	}
}
