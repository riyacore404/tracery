package tui

import "fmt"

func renderEvents(events []EventLine) string {
	if len(events) == 0 {
		return "\n(no events yet)\n"
	}
	out := "\n"
	start := 0
	if len(events) > 20 {
		start = len(events) - 20 // show most recent 20
	}
	for _, e := range events[start:] {
		out += fmt.Sprintf("[%s] %-12s %s\n", e.Timestamp.Format("15:04:05"), e.Label, e.Detail)
	}
	return out
}