package fixplan

import (
	"fmt"
	"strings"
)

const diffContext = 3

// UnifiedDiff returns a unified diff. An empty string is returned when the
// inputs are equal. Binary inputs receive a short "binary files differ" note.
func UnifiedDiff(name string, before, after []byte) string {
	if string(before) == string(after) {
		return ""
	}
	if isBinary(before) || isBinary(after) {
		return fmt.Sprintf("diff --git a/%s b/%s\nindex binary..binary 100644\n--- a/%s\n+++ b/%s\nBinary files differ\n", name, name, name, name)
	}

	a := splitDiffLines(before)
	b := splitDiffLines(after)
	ops := lineOperations(a.lines, b.lines)

	var bld strings.Builder
	fmt.Fprintf(&bld, "--- a/%s\n", name)
	fmt.Fprintf(&bld, "+++ b/%s\n", name)

	hunks := buildHunks(ops, diffContext)
	for _, h := range hunks {
		writeHunk(&bld, h, ops, a, b)
	}

	return bld.String()
}

type diffLineSet struct {
	lines     []string
	noFinalNL bool
}

func splitDiffLines(data []byte) diffLineSet {
	if len(data) == 0 {
		return diffLineSet{}
	}
	s := string(data)
	noFinalNL := !strings.HasSuffix(s, "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		// Input was exactly "\n".
		return diffLineSet{lines: []string{""}, noFinalNL: false}
	}
	lines := strings.Split(s, "\n")

	return diffLineSet{lines: lines, noFinalNL: noFinalNL}
}

func isBinary(b []byte) bool {
	n := min(len(b), 8192)
	for i := range n {
		if b[i] == 0 {
			return true
		}
	}

	return false
}

type opKind int

const (
	opEqual opKind = iota
	opDelete
	opInsert
)

type diffOp struct {
	kind opKind
	a, b int // line indexes; unused indexes are -1
}

// lineOperations computes an LCS diff. Inputs in remediation plans are small
// structured text files; the straightforward table keeps behavior transparent.
func lineOperations(a, b []string) []diffOp {
	n, m := len(a), len(b)
	if n*m > 25_000_000 {
		// Defensive fallback for unusually large lockfiles: avoid unbounded
		// memory and present the whole file as one replacement.
		ops := make([]diffOp, 0, n+m)
		for i := range n {
			ops = append(ops, diffOp{kind: opDelete, a: i, b: -1})
		}
		for j := range m {
			ops = append(ops, diffOp{kind: opInsert, a: -1, b: j})
		}

		return ops
	}

	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}

	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, diffOp{kind: opEqual, a: i, b: j})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, diffOp{kind: opDelete, a: i, b: -1})
			i++
		default:
			ops = append(ops, diffOp{kind: opInsert, a: -1, b: j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, diffOp{kind: opDelete, a: i, b: -1})
	}
	for ; j < m; j++ {
		ops = append(ops, diffOp{kind: opInsert, a: -1, b: j})
	}

	return ops
}

type hunk struct {
	start, end int // operation indexes covered by the hunk
}

func buildHunks(ops []diffOp, context int) []hunk {
	var changeIndexes []int
	for i, op := range ops {
		if op.kind != opEqual {
			changeIndexes = append(changeIndexes, i)
		}
	}
	if len(changeIndexes) == 0 {
		return nil
	}

	var hunks []hunk
	start := max(0, changeIndexes[0]-context)
	end := min(len(ops), changeIndexes[0]+context+1)

	for _, idx := range changeIndexes[1:] {
		if idx-context <= end {
			end = min(len(ops), idx+context+1)
			continue
		}
		hunks = append(hunks, hunk{start: start, end: end})
		start = max(0, idx-context)
		end = min(len(ops), idx+context+1)
	}
	hunks = append(hunks, hunk{start: start, end: end})

	return hunks
}

func writeHunk(b *strings.Builder, h hunk, ops []diffOp, before, after diffLineSet) {
	var oldCount, newCount int
	oldStart := -1
	newStart := -1
	for i := h.start; i < h.end; i++ {
		op := ops[i]
		if op.a >= 0 {
			oldCount++
			if oldStart == -1 {
				oldStart = op.a + 1
			}
		}
		if op.b >= 0 {
			newCount++
			if newStart == -1 {
				newStart = op.b + 1
			}
		}
	}

	// Zero-count sides use the line immediately before the insertion/deletion.
	if oldCount == 0 {
		for i := h.start; i < h.end; i++ {
			if ops[i].kind == opInsert {
				oldStart = ops[i].b
				break
			}
		}
	}
	if newCount == 0 {
		for i := h.start; i < h.end; i++ {
			if ops[i].kind == opDelete {
				newStart = ops[i].a
				break
			}
		}
	}

	fmt.Fprintf(b, "@@ -%d", oldStart)
	if oldCount != 1 {
		fmt.Fprintf(b, ",%d", oldCount)
	}
	fmt.Fprintf(b, " +%d", newStart)
	if newCount != 1 {
		fmt.Fprintf(b, ",%d", newCount)
	}
	b.WriteString(" @@\n")

	for i := h.start; i < h.end; i++ {
		op := ops[i]
		switch op.kind {
		case opEqual:
			fmt.Fprintf(b, " %s\n", before.lines[op.a])
		case opDelete:
			fmt.Fprintf(b, "-%s\n", before.lines[op.a])
			if op.a == len(before.lines)-1 && before.noFinalNL {
				b.WriteString("\\ No newline at end of file\n")
			}
		case opInsert:
			fmt.Fprintf(b, "+%s\n", after.lines[op.b])
			if op.b == len(after.lines)-1 && after.noFinalNL {
				b.WriteString("\\ No newline at end of file\n")
			}
		}
	}
}
