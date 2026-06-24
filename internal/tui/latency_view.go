package tui

import "fmt"

func renderLatency(buckets []LatencyBucket) string {
	if len(buckets) == 0 {
		return "\n(no data yet)\n"
	}
	out := "\nLATENCY RANGE             COUNT  DISTRIBUTION\n"
	out += "─────────────────────────────────────────────\n"
	var max uint64
	for _, b := range buckets {
		if b.Count > max {
			max = b.Count
		}
	}
	for _, b := range buckets {
		barLen := 0
		if max > 0 {
			barLen = int(float64(b.Count) / float64(max) * 40)
		}
		bar := barStyle.Render(repeat("█", barLen))
		out += fmt.Sprintf("%-24s %6d  %s\n", b.RangeLabel, b.Count, bar)
	}
	return out
}