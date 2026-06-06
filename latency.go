package main

import (
	"fmt"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	"github.com/riyacore/tracery/internal/logger"
)

// arm64SyscallNr maps syscall names to ARM64 numbers.
// The user passes --syscall read and we look up 63.
var arm64SyscallNr = map[string]uint32{
	"read":    63,
	"write":   64,
	"openat":  56,
	"close":   57,
	"mmap":    222,
	"munmap":  81,
	"futex":   98,
	"recvfrom": 22,
	"sendto":  206,
	"stat":    80,
}

const maxBuckets = 32

// readHistogram reads all 32 buckets from the BPF array map.
func readHistogram(m *ebpf.Map) ([maxBuckets]uint64, error) {
	var buckets [maxBuckets]uint64
	for i := uint32(0); i < maxBuckets; i++ {
		var val uint64
		if err := m.Lookup(&i, &val); err == nil {
			buckets[i] = val
		}
	}
	return buckets, nil
}

// formatNs converts nanoseconds to a human-readable range label.
// e.g. bucket 10 → "1µs - 2µs"
func formatBucketRange(bucket int) string {
	low := math.Pow(2, float64(bucket-1))
	high := math.Pow(2, float64(bucket))

	formatVal := func(ns float64) string {
		switch {
		case ns < 1000:
			return fmt.Sprintf("%.0fns", ns)
		case ns < 1_000_000:
			return fmt.Sprintf("%.0fµs", ns/1000)
		default:
			return fmt.Sprintf("%.0fms", ns/1_000_000)
		}
	}

	if bucket == 0 {
		return "0 - 1ns"
	}
	return fmt.Sprintf("%s - %s", formatVal(low), formatVal(high))
}

// printHistogram renders the histogram as an ASCII bar chart.
func printHistogram(buckets [maxBuckets]uint64, syscallName string, pid uint32, elapsed int) {
	fmt.Print("\033[2J\033[H")
	fmt.Printf("tracery latency — PID %d — syscall: %s — %ds elapsed\n",
		pid, syscallName, elapsed)
	fmt.Println("─────────────────────────────────────────────────────────")

	// Find the max count for scaling the bars
	var maxCount uint64
	for _, c := range buckets {
		if c > maxCount {
			maxCount = c
		}
	}

	// Only show buckets that have data, plus some context
	// Find first and last non-zero bucket
	first, last := -1, -1
	for i, c := range buckets {
		if c > 0 {
			if first == -1 {
				first = i
			}
			last = i
		}
	}

	if first == -1 {
		fmt.Println("(no data yet — make sure the target process is making syscalls)")
		return
	}

	// Add 2 buckets of padding on each side for context
	showFrom := first - 2
	if showFrom < 0 {
		showFrom = 0
	}
	showTo := last + 2
	if showTo >= maxBuckets {
		showTo = maxBuckets - 1
	}

	fmt.Printf("%-20s %8s  %s\n", "LATENCY RANGE", "COUNT", "DISTRIBUTION")
	fmt.Println("─────────────────────────────────────────────────────────")

	barWidth := 40 // max bar width in characters

	for i := showFrom; i <= showTo; i++ {
		count := buckets[i]
		label := formatBucketRange(i)

		// Scale bar length relative to max count
		barLen := 0
		if maxCount > 0 {
			barLen = int(float64(count) / float64(maxCount) * float64(barWidth))
		}

		bar := ""
		for j := 0; j < barLen; j++ {
			bar += "█"
		}

		fmt.Printf("%-20s %8d  |%s\n", label, count, bar)
	}

	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Println("Each row = one power-of-2 latency bucket")
	fmt.Println("Tall bars = most syscalls fall in that latency range")
}

var latencyCmd = &cobra.Command{
	Use:   "latency",
	Short: "Show latency histogram for a syscall",
	Long: `Measure how long a specific syscall takes and display
results as a live ASCII histogram.

Examples:
  tracery latency --pid 1234 --syscall read
  tracery latency --pid 1234 --syscall write
  tracery latency --pid 1234 --syscall openat`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		syscallArg, _ := cmd.Flags().GetString("syscall")
		interval, _ := cmd.Flags().GetInt("interval")

		if pid == 0 {
			return fmt.Errorf("--pid is required")
		}

		syscallNr, ok := arm64SyscallNr[syscallArg]
		if !ok {
			return fmt.Errorf("unknown syscall %q — supported: read, write, openat, close, mmap, futex", syscallArg)
		}

		// Init logger for this command
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")
		pretty, _ := cmd.Root().PersistentFlags().GetBool("pretty")
		logger.Init(pretty, verbose)

		log.Info().
			Uint32("pid", pid).
			Str("syscall", syscallArg).
			Uint32("syscall_nr", syscallNr).
			Msg("starting latency tracer")

		// Remove memlock limit
		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("removing memlock: %w", err)
		}

		// Load BPF spec
		spec, err := ebpf.LoadCollectionSpec("bpf/latency.bpf.o")
		if err != nil {
			return fmt.Errorf("loading BPF spec: %w", err)
		}

		// Set constants before loading
		if err := spec.RewriteConstants(map[string]interface{}{
			"target_pid":     pid,
			"target_syscall": syscallNr,
		}); err != nil {
			return fmt.Errorf("setting constants: %w", err)
		}

		// Load into kernel — verifier runs here
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return fmt.Errorf("loading BPF collection: %w", err)
		}
		defer coll.Close()

		// Attach both probes
		enterTP, err := link.Tracepoint("raw_syscalls", "sys_enter",
			coll.Programs["handle_enter"], nil)
		if err != nil {
			return fmt.Errorf("attaching sys_enter: %w", err)
		}
		defer enterTP.Close()

		exitTP, err := link.Tracepoint("raw_syscalls", "sys_exit",
			coll.Programs["handle_exit"], nil)
		if err != nil {
			return fmt.Errorf("attaching sys_exit: %w", err)
		}
		defer exitTP.Close()

		log.Info().Msg("latency tracer attached — collecting data")

		histMap := coll.Maps["histogram"]

		// Signal handling
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		elapsed := 0

		for {
			select {
			case <-sig:
				log.Info().Msg("shutting down latency tracer")
				return nil

			case <-ticker.C:
				elapsed += interval
				buckets, err := readHistogram(histMap)
				if err != nil {
					log.Error().Err(err).Msg("failed to read histogram")
					continue
				}
				printHistogram(buckets, syscallArg, pid, elapsed)
			}
		}
	},
}

func init() {
	latencyCmd.Flags().Uint32("pid", 0, "PID of process to trace (required)")
	latencyCmd.Flags().String("syscall", "read", "syscall to measure latency for")
	latencyCmd.Flags().Int("interval", 2, "refresh interval in seconds")
}