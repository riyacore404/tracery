package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/riyacore/tracery/internal/logger"
)

// Event type constants — must match events.bpf.c exactly
const (
	eventMemMmap    = 1
	eventMemMunmap  = 2
	eventMemBrk     = 3
	eventSchedSwitch = 4
)

// Event struct — must match struct event in events.bpf.c exactly.
// Field order, sizes, and padding must be identical.
type kernelEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	Type      uint8
	_         [7]uint8  // padding to align Comm to 8-byte boundary
	Comm      [16]byte
	Addr      uint64
	Size      uint64
	PrevPID   uint32
	NextPID   uint32
	NextComm  [16]byte
}

// parseComm converts a null-terminated [16]byte to a Go string
func parseComm(b [16]byte) string {
	s := b[:]
	if idx := bytes.IndexByte(s, 0); idx != -1 {
		s = s[:idx]
	}
	return string(s)
}

// formatBytes makes byte sizes human-readable
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

// printEvent formats and prints a single event to stdout
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
		fmt.Printf("[%12.3fms] SWITCH  %-16s(%-6d) → %-16s(%-6d)\n",
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
  tracery events --pid 1234 --type mem
  tracery events --pid 1234 --type sched
  tracery events --pid 1234 --type all`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		typeFilter, _ := cmd.Flags().GetString("type")

		if pid == 0 {
			return fmt.Errorf("--pid is required")
		}
		if typeFilter != "mem" && typeFilter != "sched" && typeFilter != "all" {
			return fmt.Errorf("--type must be mem, sched, or all")
		}

		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")
		pretty, _ := cmd.Root().PersistentFlags().GetBool("pretty")
		logger.Init(pretty, verbose)

		log.Info().
			Uint32("pid", pid).
			Str("type", typeFilter).
			Msg("starting event stream")

		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("removing memlock: %w", err)
		}

		spec, err := ebpf.LoadCollectionSpec("bpf/events.bpf.o")
		if err != nil {
			return fmt.Errorf("loading BPF spec: %w", err)
		}

		// Set which event types to capture
		captureMem := uint8(0)
		captureSched := uint8(0)
		if typeFilter == "mem" || typeFilter == "all" {
			captureMem = 1
		}
		if typeFilter == "sched" || typeFilter == "all" {
			captureSched = 1
		}

		if err := spec.RewriteConstants(map[string]interface{}{
			"target_pid":    pid,
			"capture_mem":   captureMem,
			"capture_sched": captureSched,
		}); err != nil {
			return fmt.Errorf("setting constants: %w", err)
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return fmt.Errorf("loading BPF collection: %w", err)
		}
		defer coll.Close()

		// Attach all probes — unused ones are disabled via constants
		type tpAttach struct {
			category string
			name     string
			prog     string
		}

		attachPoints := []tpAttach{
			{"syscalls", "sys_enter_mmap", "trace_mmap"},
			{"syscalls", "sys_enter_munmap", "trace_munmap"},
			{"syscalls", "sys_enter_brk", "trace_brk"},
			{"sched", "sched_switch", "trace_sched_switch"},
		}

		var links []link.Link
		for _, ap := range attachPoints {
			prog, ok := coll.Programs[ap.prog]
			if !ok {
				log.Warn().Str("prog", ap.prog).Msg("program not found in collection")
				continue
			}
			l, err := link.Tracepoint(ap.category, ap.name, prog, nil)
			if err != nil {
				log.Warn().
					Str("tracepoint", ap.category+"/"+ap.name).
					Err(err).
					Msg("failed to attach tracepoint — skipping")
				continue
			}
			links = append(links, l)
			log.Debug().
				Str("tracepoint", ap.category+"/"+ap.name).
				Msg("attached")
		}
		defer func() {
			for _, l := range links {
				if err := l.Close(); err != nil {
					log.Warn().Err(err).Msg("error closing link")
				}
			}
		}()

		rd, err := ringbuf.NewReader(coll.Maps["events"])
		if err != nil {
			return fmt.Errorf("opening ring buffer: %w", err)
		}
		defer func() {
			if err := rd.Close(); err != nil {
				log.Warn().Err(err).Msg("error closing ring buffer reader")
			}
		}()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sig
			log.Info().Msg("shutting down event stream")
			if err := rd.Close(); err != nil {
				log.Warn().Err(err).Msg("error closing ring buffer on signal")
			}
		}()

		fmt.Printf("Streaming %s events for PID %d — Ctrl+C to stop\n", typeFilter, pid)
		fmt.Println("─────────────────────────────────────────────────────────────────")

		// Event loop — same pattern as mini 3
		for {
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					return nil
				}
				log.Error().Err(err).Msg("ring buffer read error")
				continue
			}

			var e kernelEvent
			if err := binary.Read(
				bytes.NewReader(record.RawSample),
				binary.NativeEndian,
				&e,
			); err != nil {
				log.Debug().Err(err).Msg("failed to parse event")
				continue
			}

			printEvent(&e, typeFilter)
		}
	},
}

func init() {
	eventsCmd.Flags().Uint32("pid", 0, "PID of process to trace (required)")
	eventsCmd.Flags().String("type", "all",
		"event types to capture: mem, sched, or all")
}