package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"time"
	"unsafe"

	bpfloader "github.com/riyacore/tracery/internal/bpf"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Measure Tracery's CPU overhead on a target workload",
	Long: `Measures overhead by running a workload twice — once untraced, once
traced — and computing the delta.

Primary method: hardware instruction counters via perf_event_open.
Fallback method: wall-clock timing (used automatically when hardware PMU
counters are unavailable, e.g. VirtualBox, most cloud VMs).

Hardware PMU requires bare metal or a KVM VM with PMU passthrough (-cpu host,+pmu).
Wall-clock timing is reproducible and sufficient for demonstrating the overhead
difference between eBPF tracing and ptrace-based tools like strace.

Examples:
  sudo tracery bench --workload "bash workload.sh" --duration 10s
  sudo tracery bench --pid 1234 --duration 5s`,
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
	benchCmd.Flags().StringVar(&benchWorkload, "workload", "", "shell command to run as workload (re-run for traced phase)")
	rootCmd.AddCommand(benchCmd)
}

// perfOpen opens a perf_event_open fd for hardware instruction counting.
// Returns (fd, nil) on success, (-1, err) if hardware PMU is unavailable.
func perfOpen(pid int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_INSTRUCTIONS,
		Bits:   unix.PerfBitDisabled | unix.PerfBitExcludeKernel,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	fd, err := unix.PerfEventOpen(&attr, pid, -1, -1, 0)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open: %w", err)
	}
	return fd, nil
}

// hardwarePMUAvailable returns true if hardware instruction counters work on
// this system. VirtualBox and most cloud VMs return false.
func hardwarePMUAvailable() bool {
	fd, err := perfOpen(os.Getpid())
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// measureInstructions counts hardware instructions executed by pid over duration.
func measureInstructions(pid int, duration time.Duration) (uint64, error) {
	fd, err := perfOpen(pid)
	if err != nil {
		return 0, err
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			log.Warn().Err(err).Msg("error closing perf fd")
		}
	}()

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_RESET, 0); err != nil {
		return 0, fmt.Errorf("resetting perf counter: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_ENABLE, 0); err != nil {
		return 0, fmt.Errorf("enabling perf counter: %w", err)
	}

	time.Sleep(duration)

	if err := unix.IoctlSetInt(fd, unix.PERF_EVENT_IOC_DISABLE, 0); err != nil {
		return 0, fmt.Errorf("disabling perf counter: %w", err)
	}

	var count uint64
	if err := binary.Read(os.NewFile(uintptr(fd), "perf"), binary.NativeEndian, &count); err != nil {
		return 0, fmt.Errorf("reading perf counter: %w", err)
	}
	return count, nil
}

// runWorkload runs a shell command and returns its wall-clock duration.
func runWorkload(command string) (time.Duration, error) {
	cmd := exec.Command("bash", "-c", command)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	start := time.Now()
	if err := cmd.Run(); err != nil {
		// non-zero exit is ok for benchmark purposes — record the time anyway
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			return 0, fmt.Errorf("running workload: %w", err)
		}
	}
	return time.Since(start), nil
}

func runBench(cmd *cobra.Command, args []string) error {
	if benchPID == 0 && benchWorkload == "" {
		return fmt.Errorf("either --pid or --workload is required")
	}

	useHardwarePMU := hardwarePMUAvailable()
	if !useHardwarePMU {
		log.Warn().Msg("hardware PMU counters not available (VirtualBox / cloud VM without PMU passthrough) — using wall-clock timing")
		log.Warn().Msg("for instruction-count measurement, run on bare metal or KVM with -cpu host,+pmu")
	}

	// ── Wall-clock mode (workload re-run) ─────────────────────────────────────
	if benchWorkload != "" {
		fmt.Printf("\n── Tracery Overhead Benchmark (wall-clock) ─────────────\n")
		fmt.Printf("  Workload:  %s\n", benchWorkload)
		fmt.Printf("  Mode:      %s\n", func() string {
			if useHardwarePMU {
				return "hardware PMU available — using wall-clock (workload mode)"
			}
			return "wall-clock (hardware PMU unavailable)"
		}())
		fmt.Println()

		// Phase 1: baseline (untraced)
		fmt.Println("  Phase 1/2: running workload untraced...")
		baselineWall, err := runWorkload(benchWorkload)
		if err != nil {
			return fmt.Errorf("baseline run: %w", err)
		}
		fmt.Printf("  Baseline:  %s\n\n", baselineWall.Round(time.Millisecond))

		// Phase 2: traced
		fmt.Println("  Phase 2/2: running workload under Tracery...")

		// Start the workload
		tracedCmd := exec.Command("bash", "-c", benchWorkload)
		tracedCmd.Stdout = os.Stdout
		tracedCmd.Stderr = os.Stderr
		if err := tracedCmd.Start(); err != nil {
			return fmt.Errorf("starting traced workload: %w", err)
		}
		wPID := tracedCmd.Process.Pid

		// Attach tracer
		tracer, err := bpfloader.NewTracer("bpf/syscall_counter.bpf.o", uint32(wPID))
		if err != nil {
			_ = tracedCmd.Process.Kill()
			return fmt.Errorf("attaching tracer: %w", err)
		}

		tracedStart := time.Now()
		if err := tracedCmd.Wait(); err != nil {
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) {
				tracer.Close()
				return fmt.Errorf("traced workload: %w", err)
			}
		}
		tracedWall := time.Since(tracedStart)
		tracer.Close()

		var overhead float64
		if baselineWall > 0 {
			overhead = (float64(tracedWall) - float64(baselineWall)) / float64(baselineWall) * 100
		}
		if overhead < 0 {
			overhead = 0 // noise
		}

		fmt.Printf("  Traced:    %s\n", tracedWall.Round(time.Millisecond))
		fmt.Printf("  Delta:     %+.0fms\n", float64(tracedWall-baselineWall)/float64(time.Millisecond))
		fmt.Printf("  Overhead:  %.1f%%\n", overhead)
		fmt.Println("────────────────────────────────────────────────────────")
		if overhead < 3.0 {
			fmt.Println("  ✓ Within <3% overhead target")
		} else {
			fmt.Printf("  ⚠ %.1f%% — above 3%% target (high syscall rate or VM scheduling noise)\n", overhead)
		}
		if !useHardwarePMU {
			fmt.Println()
			fmt.Println("  Note: hardware PMU unavailable — wall-clock delta includes VM")
			fmt.Println("  scheduling noise. Run 3+ times and take the median for accuracy.")
			fmt.Println("  See ARCHITECTURE.md §Overhead Measurement for methodology.")
		}
		fmt.Println()
		return nil
	}

	// ── PID mode (hardware PMU, attach to running process) ────────────────────
	pid := benchPID
	if !useHardwarePMU {
		fmt.Println()
		fmt.Println("── Tracery Overhead Benchmark ──────────────────────────")
		fmt.Printf("  PID:      %d\n", pid)
		fmt.Println()
		fmt.Println("  ✗ Hardware PMU counters not available on this system.")
		fmt.Println("    perf_event_open(PERF_COUNT_HW_INSTRUCTIONS) requires")
		fmt.Println("    bare metal or KVM with PMU passthrough.")
		fmt.Println()
		fmt.Println("  Use --workload instead for wall-clock measurement:")
		fmt.Println("    sudo tracery bench --workload \"bash workload.sh\" --duration 10s")
		fmt.Println("────────────────────────────────────────────────────────")
		fmt.Println()
		return nil
	}

	log.Info().Int("pid", pid).Dur("duration", benchDuration).Msg("measuring baseline (untraced)")
	baseline, err := measureInstructions(pid, benchDuration)
	if err != nil {
		return fmt.Errorf("baseline measurement: %w", err)
	}
	log.Info().Uint64("instructions", baseline).Msg("baseline complete")

	tracer, err := bpfloader.NewTracer("bpf/syscall_counter.bpf.o", uint32(pid))
	if err != nil {
		return fmt.Errorf("attaching tracer: %w", err)
	}
	defer tracer.Close()

	log.Info().Msg("tracer attached — measuring overhead")
	traced, err := measureInstructions(pid, benchDuration)
	if err != nil {
		return fmt.Errorf("traced measurement: %w", err)
	}
	log.Info().Uint64("instructions", traced).Msg("traced measurement complete")

	var overhead float64
	if baseline > 0 && traced > baseline {
		overhead = float64(traced-baseline) / float64(baseline) * 100
	}

	fmt.Println()
	fmt.Println("── Tracery Overhead Benchmark (instruction count) ───────")
	fmt.Printf("  PID:         %d\n", pid)
	fmt.Printf("  Duration:    %s per run\n", benchDuration)
	fmt.Printf("  Baseline:    %s instructions\n", commaSep(baseline))
	fmt.Printf("  Traced:      %s instructions\n", commaSep(traced))
	if traced > baseline {
		fmt.Printf("  Delta:       +%s instructions\n", commaSep(traced-baseline))
	} else {
		fmt.Printf("  Delta:       ~0 (within measurement noise)\n")
	}
	fmt.Printf("  Overhead:    %.2f%%\n", overhead)
	fmt.Println("────────────────────────────────────────────────────────")
	if overhead < 3.0 {
		fmt.Println("  ✓ Within <3% overhead target")
	} else {
		fmt.Println("  ⚠ Above 3% target — high syscall rate workload")
	}
	fmt.Println()
	return nil
}

func commaSep(n uint64) string {
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