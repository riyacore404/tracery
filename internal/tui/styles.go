package tui

import "github.com/charmbracelet/lipgloss"

var (
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("212")).
			Padding(0, 1)

	activeTabStyle = lipgloss.NewStyle().
			Bold(true).
			Underline(true)

	barStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("63"))
)

func renderHeader(pid uint32, active View) string {
	tabs := []string{"Syscalls", "Latency", "Events"}
	rendered := make([]string, len(tabs))
	for i, t := range tabs {
		if View(i) == active {
			rendered[i] = activeTabStyle.Render(t)
		} else {
			rendered[i] = t
		}
	}
	line := ""
	for i, r := range rendered {
		if i > 0 {
			line += "   "
		}
		line += r
	}
	return headerStyle.Render("tracery dashboard") + "  pid=" + itoa(pid) + "\n" + line
}

func itoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}