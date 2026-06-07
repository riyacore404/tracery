package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
	"unsafe"

	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"

	bpfloader "github.com/riyacore/tracery/internal/bpf"
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Measure Tracery's overhead on a target process",
	Long: `Runs a workload twice — once untraced, once traced — and reports
the CPU instruction count delta using perf_event_open.

Examples:
  sudo tracery bench --pid 1234 --duration 5s
  sudo tracery bench --workload "curl https://example.com" --duration 10s`,
	RunE: runBench,
}

var (
	benchPID      int
	benchDuration time.Duration
	benchWorkload string
)

func init() {
	benchCmd.Flags().IntVar(&benchPID, "pid", 0, "PID of running process to benchmark")
	benchCmd.Flags().DurationVar(&benchDuration, "duration", 5*time.Second, "measurement window per run")
	benchCmd.Flags().StringVar(&benchWorkload, "workload", "", "shell command to run as workload (alternative to --pid)")
	rootCmd.AddCommand(benchCmd)
}

// perfEventOpen opens a perf_event counter for instruction counting on a PID.
func perfEventOpen(pid int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_INSTRUCTIONS,
		Bits:   unix.PerfBitDisabled | unix.PerfBitExcludeKernel,
	}
	attr.Size = uint32(unsafe.Sizeof(attr))
	fd, err := unix.PerfEventOpen(&attr, pid, -1, -1, 0)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open: %w", err)
	}
	return fd, nil
}

// countInstructions measures CPU instructions for a PID over a duration.
func countInstructions(pid int, duration time.Duration) (uint64, error) {
	fd, err := perfEventOpen(pid)
	if err != nil {
		return 0, err
	}
	defer unix.Close(fd)

	// Enable counting
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return 0, fmt.Errorf("enabling perf counter: %w", err)
	}

	time.Sleep(duration)

	// Disable counting
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		return 0, fmt.Errorf("disabling perf counter: %w", err)
	}

	// Read the count
	var count uint64
	if err := binary.Read(os.NewFile(uintptr(fd), "perf"), binary.NativeEndian, &count); err != nil {
		return 0, fmt.Errorf("reading perf counter: %w", err)
	}
	return count, nil
}

func runBench(cmd *cobra.Command, args []string) error {
	if benchPID == 0 && benchWorkload == "" {
		return fmt.Errorf("either --pid or --workload is required")
	}

	pid := benchPID

	// If workload flag used, start the process
	if benchWorkload != "" {
		proc := exec.Command("bash", "-c", benchWorkload)
		proc.Stdout = os.Stdout
		proc.Stderr = os.Stderr
		if err := proc.Start(); err != nil {
			return fmt.Errorf("starting workload: %w", err)
		}
		pid = proc.Process.Pid
		defer func() {
			_ = proc.Process.Kill()
		}()
	}

	log.Info().
		Int("pid", pid).
		Dur("duration", benchDuration).
		Msg("measuring baseline (untraced)")

	// Run 1: untraced
	baseline, err := countInstructions(pid, benchDuration)
	if err != nil {
		return fmt.Errorf("baseline measurement: %w", err)
	}

	log.Info().Uint64("instructions", baseline).Msg("baseline complete")
	log.Info().Msg("attaching tracer for overhead measurement")

	// Attach tracer
	tracer, err := bpfloader.NewTracer("bpf/syscall_counter.bpf.o", uint32(pid))
	if err != nil {
		return fmt.Errorf("attaching tracer: %w", err)
	}
	defer tracer.Close()

	log.Info().Msg("measuring with tracer attached")

	// Run 2: traced
	traced, err := countInstructions(pid, benchDuration)
	if err != nil {
		return fmt.Errorf("traced measurement: %w", err)
	}

	log.Info().Uint64("instructions", traced).Msg("traced measurement complete")

	// Compute overhead
	var overhead float64
	if baseline > 0 {
		overhead = float64(traced-baseline) / float64(baseline) * 100
	}

	// Print results
	fmt.Println()
	fmt.Println("── Tracery Overhead Benchmark ──────────────────────")
	fmt.Printf("  PID:              %d\n", pid)
	fmt.Printf("  Duration:         %s per run\n", benchDuration)
	fmt.Printf("  Baseline:         %s instructions\n", formatNum(baseline))
	fmt.Printf("  Traced:           %s instructions\n", formatNum(traced))
	fmt.Printf("  Delta:            %s instructions\n", formatNum(traced-baseline))
	fmt.Printf("  Overhead:         %.2f%%\n", overhead)
	fmt.Println("────────────────────────────────────────────────────")

	if overhead < 3.0 {
		fmt.Println("  ✓ Within target overhead (<3%)")
	} else {
		fmt.Printf("  ⚠ Overhead above 3%% target — consider --mode=count-only\n")
	}
	fmt.Println()

	return nil
}

func formatNum(n uint64) string {
	s := strconv.FormatUint(n, 10)
	out := ""
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(c)
	}
	return out
}