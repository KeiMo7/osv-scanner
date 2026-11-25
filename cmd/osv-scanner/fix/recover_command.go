package fix

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/osv-scanner/v2/internal/fixplan"
	"github.com/urfave/cli/v3"
)

func recoverCommand(stdout io.Writer) *cli.Command {
	return &cli.Command{
		Name:  "recover",
		Usage: "recover interrupted fix apply transactions",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "state-dir", Usage: "transaction state directory"},
			&cli.StringFlag{Name: "format", Aliases: []string{"f"}, Value: "text", Usage: "output format: text, json"},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			recovered, err := fixplan.Recover(fixplan.ApplyOptions{StateDir: cmd.String("state-dir")})
			if cmd.String("format") == "json" {
				out := map[string]any{"ok": err == nil, "recovered": recovered}
				if err != nil {
					out["error"] = safeError(err)
				}

				return writeJSON(stdout, out)
			}
			for _, id := range recovered {
				fmt.Fprintf(stdout, "RECOVERED: %s\n", id)
			}
			if err == nil {
				fmt.Fprintln(stdout, "RECOVER-OK")
			}

			return redactError(err)
		},
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")

	return enc.Encode(v)
}
