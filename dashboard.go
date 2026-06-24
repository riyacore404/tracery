package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"

	bpfloader "github.com/riyacore/tracery/internal/bpf"
	"github.com/riyacore/tracery/internal/tui"
)

var dashboardPID int

var dashboardCmd = &cobra.Command{
	Use:     "dashboard",
	Short:   "Live full-screen TUI: syscalls, latency, and events in one view",
	Example: `  sudo tracery dashboard --pid 1234`,
	RunE:    runDashboard,
}

var dashboardSyscall string

func init() {
	dashboardCmd.Flags().IntVar(&dashboardPID, "pid", 0, "Target process PID (required)")
	dashboardCmd.Flags().StringVar(&dashboardSyscall, "syscall", "read", "syscall to track in the latency tab")
	if err := dashboardCmd.MarkFlagRequired("pid"); err != nil {
		panic(err)
	}
	rootCmd.AddCommand(dashboardCmd)
}

func runDashboard(cmd *cobra.Command, args []string) error {
	pid := uint32(dashboardPID)
	model := tui.NewModel(pid)
	p := tea.NewProgram(model, tea.WithAltScreen())

	stop := make(chan struct{})
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		close(stop)
		p.Quit()
	}()

	go func() {
		_ = bpfloader.PollSyscallCounts(pid, time.Second, syscallName, func(rows []bpfloader.SyscallCount) {
			out := make([]tui.SyscallCount, len(rows))
			for i, r := range rows {
				out[i] = tui.SyscallCount{Name: r.Name, Count: r.Count}
			}
			p.Send(tui.NewSyscallDataMsg(out))
		}, stop)
	}()

	go func() {
		// Default to "read" latency in the dashboard's latency tab; could be
		// made a --syscall flag on dashboardCmd later.
		nr, ok := arm64SyscallNr[dashboardSyscall]
		if !ok {
			nr = arm64SyscallNr["read"] // fallback
		}
		_ = bpfloader.PollLatencyHistogram(pid, nr, time.Second, func(buckets [bpfloader.MaxLatencyBuckets]uint64) {
			rows := make([]tui.LatencyBucket, 0, bpfloader.MaxLatencyBuckets)
			for i, c := range buckets {
				if c == 0 {
					continue
				}
				rows = append(rows, tui.LatencyBucket{RangeLabel: formatBucketRange(i), Count: c})
			}
			p.Send(tui.NewLatencyDataMsg(rows))
		}, stop)
	}()

	go func() {
		_ = bpfloader.PollEvents(pid, "all", func(e bpfloader.KernelEvent) {
			p.Send(tui.NewEventDataMsg(tui.EventLine{
				Timestamp: time.Now(),
				Label:     eventLabel(e.Type),
				Detail:    fmt.Sprintf("pid=%d", e.PID),
			}))
		}, stop)
	}()

	if _, err := p.Run(); err != nil {
		return fmt.Errorf("running dashboard: %w", err)
	}
	return nil
}

func eventLabel(t uint8) string {
	switch t {
	case bpfloader.EventMemMmap:
		return "MMAP"
	case bpfloader.EventMemMunmap:
		return "MUNMAP"
	case bpfloader.EventMemBrk:
		return "BRK"
	case bpfloader.EventSchedSwitch:
		return "SWITCH"
	default:
		return "UNKNOWN"
	}
}