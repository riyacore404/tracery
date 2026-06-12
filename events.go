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
)

const (
	eventMemMmap     = 1
	eventMemMunmap   = 2
	eventMemBrk      = 3
	eventSchedSwitch = 4
)

// kernelEvent must match struct event in events.bpf.c exactly.
//
// ARM64 layout (verified against C struct with explicit _pad[7]):
//   timestamp  u64    offset 0   size 8
//   pid        u32    offset 8   size 4
//   tid        u32    offset 12  size 4
//   type       u8     offset 16  size 1
//   comm[16]   char   offset 17  size 16
//   _pad[7]    u8     offset 33  size 7   ← aligns addr to offset 40
//   addr       u64    offset 40  size 8
//   size       u64    offset 48  size 8
//   prev_pid   u32    offset 56  size 4
//   next_pid   u32    offset 60  size 4
//   next_comm  char   offset 64  size 16
//   total: 80 bytes
type kernelEvent struct {
	Timestamp uint64
	PID       uint32
	TID       uint32
	Type      uint8
	Comm      [16]byte
	Pad       [7]uint8 // explicit padding — must match C struct _pad[7]
	Addr      uint64
	Size      uint64
	PrevPID   uint32
	NextPID   uint32
	NextComm  [16]byte
}

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

		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("removing memlock: %w", err)
		}

		spec, err := ebpf.LoadCollectionSpec("bpf/events.bpf.o")
		if err != nil {
			return fmt.Errorf("loading BPF spec: %w", err)
		}

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

		// Attach the raw_syscalls probe for mem events
		var memLink link.Link
		if captureMem == 1 {
			memLink, err = link.Tracepoint("raw_syscalls", "sys_enter",
				coll.Programs["trace_mem_syscalls"], nil)
			if err != nil {
				return fmt.Errorf("attaching raw_syscalls/sys_enter: %w", err)
			}
			defer func() {
				if err := memLink.Close(); err != nil {
					log.Warn().Err(err).Msg("error closing mem link")
				}
			}()
			log.Debug().Msg("attached raw_syscalls/sys_enter for mem events")
		}

		// Attach the sched_switch probe
		var schedLink link.Link
		if captureSched == 1 {
			schedLink, err = link.Tracepoint("sched", "sched_switch",
				coll.Programs["trace_sched_switch"], nil)
			if err != nil {
				return fmt.Errorf("attaching sched/sched_switch: %w", err)
			}
			defer func() {
				if err := schedLink.Close(); err != nil {
					log.Warn().Err(err).Msg("error closing sched link")
				}
			}()
			log.Debug().Msg("attached sched/sched_switch")
		}

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
				log.Debug().
					Int("raw_len", len(record.RawSample)).
					Int("struct_size", binary.Size(kernelEvent{})).
					Err(err).
					Msg("failed to parse event — struct size mismatch?")
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