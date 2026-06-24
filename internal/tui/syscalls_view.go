package tui

import "fmt"

func renderSyscalls(rows []SyscallCount) string {
	if len(rows) == 0 {
		return "\n(no data yet — waiting for syscalls)\n"
	}
	out := "\nSYSCALL                  COUNT\n"
	out += "─────────────────────────────\n"
	max := rows[0].Count
	for _, r := range rows {
		barLen := 0
		if max > 0 {
			barLen = int(float64(r.Count) / float64(max) * 30)
		}
		bar := barStyle.Render(repeat("█", barLen))
		out += fmt.Sprintf("%-24s %8d %s\n", r.Name, r.Count, bar)
	}
	return out
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}