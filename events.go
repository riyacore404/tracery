package main

import (
	"bytes"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	bpfloader "github.com/riyacore/tracery/internal/bpf"
)

// kernelEvent is an alias for the single canonical struct definition that
// lives in internal/bpf, which must match struct event in events.bpf.c
// exactly (see internal/bpf/poll.go for the full layout documentation).
type kernelEvent = bpfloader.KernelEvent

const (
	eventMemMmap     = bpfloader.EventMemMmap
	eventMemMunmap   = bpfloader.EventMemMunmap
	eventMemBrk      = bpfloader.EventMemBrk
	eventSchedSwitch = bpfloader.EventSchedSwitch
)

// parseComm converts a null-terminated [16]byte comm field to a Go string.
func parseComm(b [16]byte) string {
	s := b[:]
	if idx := bytes.IndexByte(s, 0); idx != -1 {
		s = s[:idx]
	}
	return string(s)
}

// formatBytes makes byte sizes human-readable.
func formatBytes(b uint64) string {
	switch {
	case b == 0:
		return "heap resize"
	case b < 1024:
		return fmt.Sprintf("%dB", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1fKB", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1fMB", float64(b)/(1024*1024))
	}
}

// printEvent formats and prints a single event.
// typeFilter: "mem", "sched", or "all"
func printEvent(e *kernelEvent, typeFilter string) {
	comm := parseComm(e.Comm)
	tsMs := float64(e.Timestamp) / 1_000_000

	switch e.Type {
	case eventMemMmap:
		if typeFilter == "sched" {
			return
		}
		fmt.Printf("[%12.3fms] MMAP    pid=%-6d %-16s addr=0x%x size=%s\n",
			tsMs, e.PID, comm, e.Addr, formatBytes(e.Size))

	case eventMemMunmap:
		if typeFilter == "sched" {
			return
		}
		fmt.Printf("[%12.3fms] MUNMAP  pid=%-6d %-16s addr=0x%x size=%s\n",
			tsMs, e.PID, comm, e.Addr, formatBytes(e.Size))

	case eventMemBrk:
		if typeFilter == "sched" {
			return
		}
		fmt.Printf("[%12.3fms] BRK     pid=%-6d %-16s addr=0x%x %s\n",
			tsMs, e.PID, comm, e.Addr, formatBytes(e.Size))

	case eventSchedSwitch:
		if typeFilter == "mem" {
			return
		}
		nextComm := parseComm(e.NextComm)
		fmt.Printf("[%12.3fms] SWITCH  %-16s(%d) → %-16s(%d)\n",
			tsMs, comm, e.PrevPID, nextComm, e.NextPID)
	}
}

var eventsCmd = &cobra.Command{
	Use:   "events",
	Short: "Stream memory and scheduler events in real time",
	Long: `Stream kernel events for a target process in real time.

Event types:
  mem   — mmap, munmap, brk (memory mapping and heap events)
  sched — context switches (scheduler events)
  all   — both mem and sched events

Examples:
  sudo tracery events --pid 1234 --type mem
  sudo tracery events --pid 1234 --type sched
  sudo tracery events --pid 1234 --type all`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		typeFilter, _ := cmd.Flags().GetString("type")

		if pid == 0 {
			return fmt.Errorf("--pid is required")
		}
		if typeFilter != "mem" && typeFilter != "sched" && typeFilter != "all" {
			return fmt.Errorf("--type must be mem, sched, or all — got %q", typeFilter)
		}

		log.Info().
			Uint32("pid", pid).
			Str("type", typeFilter).
			Msg("starting event stream")

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		stop := make(chan struct{})
		go func() {
			<-sig
			log.Info().Msg("shutting down event stream")
			close(stop)
		}()

		fmt.Printf("Streaming %s events for PID %d — Ctrl+C to stop\n", typeFilter, pid)
		fmt.Println("─────────────────────────────────────────────────────────────────")

		err := bpfloader.PollEvents(pid, typeFilter, func(e bpfloader.KernelEvent) {
			printEvent(&e, typeFilter)
		}, stop)

		if err != nil {
			return fmt.Errorf("event stream failed: %w", err)
		}
		return nil
	},
}

func init() {
	eventsCmd.Flags().Uint32("pid", 0, "PID of process to trace (required)")
	eventsCmd.Flags().String("type", "all",
		"event types to capture: mem, sched, or all")
}