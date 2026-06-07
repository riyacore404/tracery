package main

import (
	"encoding/binary"
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
	Short: "Measure Tracery's CPU overhead on a target process",
	Long: `Runs a workload twice — once untraced, once traced — and reports
the CPU instruction count delta using perf_event_open.

Examples:
  sudo tracery bench --pid 1234 --duration 5s
  sudo tracery bench --workload "curl -s https://example.com" --duration 5s`,
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
	benchCmd.Flags().StringVar(&benchWorkload, "workload", "", "shell command to run as workload")
	rootCmd.AddCommand(benchCmd)
}

func perfOpen(pid int) (int, error) {
	attr := unix.PerfEventAttr{
		Type:   unix.PERF_TYPE_HARDWARE,
		Config: unix.PERF_COUNT_HW_INSTRUCTIONS,
		Bits:   unix.PerfBitDisabled | unix.PerfBitExcludeKernel,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	fd, err := unix.PerfEventOpen(&attr, pid, -1, -1, 0)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open (is CAP_PERFMON set?): %w", err)
	}
	return fd, nil
}

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

func runBench(cmd *cobra.Command, args []string) error {
	if benchPID == 0 && benchWorkload == "" {
		return fmt.Errorf("either --pid or --workload is required")
	}

	pid := benchPID

	var proc *exec.Cmd
	if benchWorkload != "" {
		proc = exec.Command("bash", "-c", benchWorkload)
		proc.Stdout = os.Stdout
		proc.Stderr = os.Stderr
		if err := proc.Start(); err != nil {
			return fmt.Errorf("starting workload: %w", err)
		}
		pid = proc.Process.Pid
		defer func() {
			if err := proc.Process.Kill(); err != nil {
				log.Warn().Err(err).Msg("killing workload process")
			}
		}()
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
	fmt.Println("── Tracery Overhead Benchmark ──────────────────────")
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
	fmt.Println("────────────────────────────────────────────────────")
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
