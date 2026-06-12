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
)

// arm64SyscallNr maps syscall names to ARM64 (aarch64) numbers.
// Source: include/uapi/asm-generic/unistd.h
var arm64SyscallNr = map[string]uint32{
	"read":     63,
	"write":    64,
	"open":     56, // openat on arm64
	"close":    57,
	"openat":   56,
	"mmap":     222,
	"munmap":   215,
	"brk":      214,
	"futex":    98,
	"recvfrom": 207,
	"sendto":   206,
	"connect":  203,
	"accept":   202,
	"accept4":  242,
	"clone":    220,
	"clone3":   435,
	"execve":   221,
	"wait4":    260,
	"exit":     93,
	"exit_group": 94,
	"mprotect": 226,
	"msync":    227,
	"mlock":    228,
	"munlock":  229,
	"socket":   198,
	"bind":     200,
	"listen":   201,
	"getpid":   172,
	"gettid":   178,
	"kill":     129,
	"tgkill":   131,
	"nanosleep": 101,
	"clock_gettime": 113,
	"clock_nanosleep": 115,
	"gettimeofday": 169,
	"pread64":  67,
	"pwrite64": 68,
	"readv":    65,
	"writev":   66,
	"lseek":    62,
	"stat":     79, // newfstatat
	"fstat":    80,
	"getdents64": 61,
	"pipe2":    59,
	"dup":      23,
	"dup3":     24,
	"epoll_create1": 20,
	"epoll_ctl":    21,
	"epoll_pwait":  22,
	"fcntl":    25,
	"ioctl":    29,
	"getrandom": 278,
	"prctl":    167,
	"sched_yield": 124,
	"rt_sigaction": 134,
	"rt_sigprocmask": 135,
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

// formatBucketRange converts a bucket index to a human-readable range label.
func formatBucketRange(bucket int) string {
	if bucket == 0 {
		return "0 - 1ns"
	}
	low := math.Pow(2, float64(bucket-1))
	high := math.Pow(2, float64(bucket))

	formatVal := func(ns float64) string {
		switch {
		case ns < 1000:
			return fmt.Sprintf("%.0fns", ns)
		case ns < 1_000_000:
			return fmt.Sprintf("%.1fµs", ns/1000)
		default:
			return fmt.Sprintf("%.1fms", ns/1_000_000)
		}
	}
	return fmt.Sprintf("%s - %s", formatVal(low), formatVal(high))
}

// printHistogram renders the histogram as an ASCII bar chart.
func printHistogram(buckets [maxBuckets]uint64, syscallName string, pid uint32, elapsed int) {
	fmt.Print("\033[2J\033[H")
	fmt.Printf("tracery latency — PID %d — syscall: %s — %ds elapsed\n",
		pid, syscallName, elapsed)
	fmt.Println("─────────────────────────────────────────────────────────")

	var maxCount uint64
	for _, c := range buckets {
		if c > maxCount {
			maxCount = c
		}
	}

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
		fmt.Println("(no data yet — make sure the target process is making this syscall)")
		return
	}

	showFrom := first - 2
	if showFrom < 0 {
		showFrom = 0
	}
	showTo := last + 2
	if showTo >= maxBuckets {
		showTo = maxBuckets - 1
	}

	fmt.Printf("%-22s %8s  %s\n", "LATENCY RANGE", "COUNT", "DISTRIBUTION")
	fmt.Println("─────────────────────────────────────────────────────────")

	barWidth := 40
	for i := showFrom; i <= showTo; i++ {
		count := buckets[i]
		label := formatBucketRange(i)
		barLen := 0
		if maxCount > 0 {
			barLen = int(float64(count) / float64(maxCount) * float64(barWidth))
		}
		bar := ""
		for j := 0; j < barLen; j++ {
			bar += "█"
		}
		fmt.Printf("%-22s %8d  |%s\n", label, count, bar)
	}

	fmt.Println("─────────────────────────────────────────────────────────")
	fmt.Println("Each row = one power-of-2 latency bucket (nanoseconds)")
}

var latencyCmd = &cobra.Command{
	Use:   "latency",
	Short: "Show latency histogram for a syscall",
	Long: `Measure how long a specific syscall takes and display
results as a live ASCII histogram.

Examples:
  sudo tracery latency --pid 1234 --syscall read
  sudo tracery latency --pid 1234 --syscall write
  sudo tracery latency --pid 1234 --syscall openat
  sudo tracery latency --pid 1234 --syscall futex`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		syscallArg, _ := cmd.Flags().GetString("syscall")
		interval, _ := cmd.Flags().GetInt("interval")

		if pid == 0 {
			return fmt.Errorf("--pid is required")
		}

		syscallNr, ok := arm64SyscallNr[syscallArg]
		if !ok {
			return fmt.Errorf(
				"unknown syscall %q\nsupported: read, write, openat, close, mmap, munmap, "+
					"brk, futex, recvfrom, sendto, connect, accept, accept4, clone, clone3, "+
					"execve, wait4, mprotect, socket, bind, listen, nanosleep, "+
					"clock_gettime, getrandom, prctl, sched_yield",
				syscallArg,
			)
		}

		log.Info().
			Uint32("pid", pid).
			Str("syscall", syscallArg).
			Uint32("syscall_nr", syscallNr).
			Msg("starting latency tracer")

		if err := rlimit.RemoveMemlock(); err != nil {
			return fmt.Errorf("removing memlock: %w", err)
		}

		spec, err := ebpf.LoadCollectionSpec("bpf/latency.bpf.o")
		if err != nil {
			return fmt.Errorf("loading BPF spec: %w", err)
		}

		if err := spec.RewriteConstants(map[string]interface{}{
			"target_pid":     pid,
			"target_syscall": syscallNr,
		}); err != nil {
			return fmt.Errorf("setting constants: %w", err)
		}

		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			return fmt.Errorf("loading BPF collection: %w", err)
		}
		defer coll.Close()

		enterTP, err := link.Tracepoint("raw_syscalls", "sys_enter",
			coll.Programs["handle_enter"], nil)
		if err != nil {
			return fmt.Errorf("attaching sys_enter: %w", err)
		}
		defer func() {
			if err := enterTP.Close(); err != nil {
				log.Warn().Err(err).Msg("error closing enterTP")
			}
		}()

		exitTP, err := link.Tracepoint("raw_syscalls", "sys_exit",
			coll.Programs["handle_exit"], nil)
		if err != nil {
			return fmt.Errorf("attaching sys_exit: %w", err)
		}
		defer func() {
			if err := exitTP.Close(); err != nil {
				log.Warn().Err(err).Msg("error closing exitTP")
			}
		}()

		log.Info().
			Str("syscall", syscallArg).
			Uint32("nr", syscallNr).
			Msg("latency tracer attached — collecting data")

		histMap := coll.Maps["histogram"]

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