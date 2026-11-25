package fix_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scanner/v2/cmd/osv-scanner/internal/testcmd"
)

func writeFixtureSource(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	return path
}

func sourceArgs(fixtures []string) []string {
	args := make([]string, 0, 7+len(fixtures))
	args = append(args, "", "fix", "resolve-source", "--format=json", "--system=npm", "--package=demo", "--version=1.2.3")
	for _, f := range fixtures {
		args = append(args, "--source=fixture:"+f)
	}

	return args
}

func TestSourceResolveCommandOrderFallbackAndFailures(t *testing.T) {
	t.Parallel()
	hit := writeFixtureSource(t, "hit.json", `{"packages":[{"system":"npm","name":"demo","versions":["1.2.3"]}]}`)
	otherVersion := writeFixtureSource(t, "other.json", `{"packages":[{"system":"npm","name":"demo","versions":["9.9.9"]}]}`)
	missing := writeFixtureSource(t, "missing.json", `{"packages":[]}`)
	unavailable := writeFixtureSource(t, "down.json", `{"unavailable":true}`)

	t.Run("priority selects first hit", func(t *testing.T) {
		t.Parallel()
		stdout, _ := testcmd.RunAndNormalize(t, testcmd.Case{
			Name:         t.Name(),
			Args:         sourceArgs([]string{hit, otherVersion}),
			Exit:         0,
			CassetteName: testcmd.NoInteractions,
		})
		var out map[string]any
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("invalid JSON: %v\n%s", err, stdout)
		}
		selected, _ := out["selected"].([]any)
		if len(selected) != 1 {
			t.Fatalf("selected = %v", out["selected"])
		}
		row := selected[0].(map[string]any)
		if row["selected_source"] != "fixture:hit.json" {
			t.Fatalf("selected source = %v", row["selected_source"])
		}
	})

	t.Run("explicit missing version falls back", func(t *testing.T) {
		t.Parallel()
		stdout, _ := testcmd.RunAndNormalize(t, testcmd.Case{
			Name:         t.Name(),
			Args:         sourceArgs([]string{otherVersion, hit}),
			Exit:         0,
			CassetteName: testcmd.NoInteractions,
		})
		if !jsonContains(stdout, `"selected_source": "fixture:hit.json"`) {
			t.Fatalf("expected fallback to hit source:\n%s", stdout)
		}
		if !jsonContains(stdout, "fallback_after_not_found") {
			t.Fatalf("missing fallback reason:\n%s", stdout)
		}
	})

	t.Run("unavailable source falls back", func(t *testing.T) {
		t.Parallel()
		stdout, _ := testcmd.RunAndNormalize(t, testcmd.Case{
			Name:         t.Name(),
			Args:         sourceArgs([]string{unavailable, hit}),
			Exit:         0,
			CassetteName: testcmd.NoInteractions,
		})
		if !jsonContains(stdout, `"selected_source": "fixture:hit.json"`) {
			t.Fatalf("expected fallback after unavailable:\n%s", stdout)
		}
		if !jsonContains(stdout, "fallback_after_source_unavailable") {
			t.Fatalf("missing unavailable fallback reason:\n%s", stdout)
		}
	})

	t.Run("all unavailable distinguishes code", func(t *testing.T) {
		t.Parallel()
		stdout, _ := testcmd.RunAndNormalize(t, testcmd.Case{
			Name:         t.Name(),
			Args:         sourceArgs([]string{unavailable, unavailable}),
			Exit:         127,
			CassetteName: testcmd.NoInteractions,
		})
		var out struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("error JSON: %v\n%s", err, stdout)
		}
		if out.Error.Code != "ALL_SOURCES_UNAVAILABLE" {
			t.Fatalf("code = %q body=%s", out.Error.Code, stdout)
		}
	})

	t.Run("all missing distinguishes no available version", func(t *testing.T) {
		t.Parallel()
		stdout, _ := testcmd.RunAndNormalize(t, testcmd.Case{
			Name:         t.Name(),
			Args:         sourceArgs([]string{missing, missing}),
			Exit:         127,
			CassetteName: testcmd.NoInteractions,
		})
		var out struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("error JSON: %v\n%s", err, stdout)
		}
		if out.Error.Code != "NO_AVAILABLE_VERSION" {
			t.Fatalf("code = %q body=%s", out.Error.Code, stdout)
		}
	})
}

func jsonContains(s, want string) bool {
	return len(s) >= len(want) && (indexString(s, want) >= 0)
}

func indexString(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}

	return -1
}
