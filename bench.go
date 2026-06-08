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
)

var benchCmd = &cobra.Command{
	Use:   "bench",
	Short: "Measure Tracery's CPU overhead on a target process",
	Long: `Measures CPU clock samples for a target process using perf_event_open.
Runs the workload for the specified duration and reports the sample rate.

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
		Type:   unix.PERF_TYPE_SOFTWARE,
		Config: unix.PERF_COUNT_SW_CPU_CLOCK,
		Bits:   unix.PerfBitDisabled | unix.PerfBitExcludeKernel,
		Size:   uint32(unsafe.Sizeof(unix.PerfEventAttr{})),
	}
	fd, err := unix.PerfEventOpen(&attr, pid, -1, -1, 0)
	if err != nil {
		return -1, fmt.Errorf("perf_event_open: %w", err)
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

	log.Info().Int("pid", pid).Dur("duration", benchDuration).Msg("measuring CPU clock samples")

	samples, err := measureInstructions(pid, benchDuration)
	if err != nil {
		return fmt.Errorf("measurement failed: %w", err)
	}

	fmt.Println()
	fmt.Println("── Tracery Overhead Benchmark ──────────────────────")
	fmt.Printf("  PID:         %d\n", pid)
	fmt.Printf("  Duration:    %s\n", benchDuration)
	fmt.Printf("  CPU samples: %s\n", commaSep(samples))
	fmt.Printf("  Rate:        %.2fM samples/sec\n",
		float64(samples)/benchDuration.Seconds()/1_000_000)
	fmt.Println("────────────────────────────────────────────────────")
	fmt.Println("  ✓ perf_event_open measurement working")
	fmt.Println("  Note: overhead delta requires hardware perf counters")
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