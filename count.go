package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	bpfloader "github.com/riyacore/tracery/internal/bpf"
)

var syscallNames = map[uint32]string{
	17:  "getcwd",
	22:  "recvfrom",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	28:  "mlock",
	29:  "munlock",
	56:  "openat",
	57:  "close",
	61:  "getdents64",
	62:  "lseek",
	63:  "read",
	64:  "write",
	65:  "readv",
	66:  "writev",
	72:  "pselect6",
	73:  "ppoll",
	76:  "brk",
	78:  "mmap",
	80:  "mprotect",
	81:  "munmap",
	93:  "exit",
	94:  "exit_group",
	96:  "set_tid_address",
	98:  "futex",
	99:  "set_robust_list",
	113: "clock_gettime",
	116: "clock_getres",
	117: "clock_nanosleep",
	134: "execveat",
	135: "clone3",
	139: "faccessat2",
	160: "uname",
	172: "getpid",
	173: "getppid",
	174: "getuid",
	175: "geteuid",
	176: "getgid",
	177: "getegid",
	178: "gettid",
	198: "socket",
	203: "connect",
	207: "sendmmsg",
	208: "tgkill",
	209: "timerfd_settime",
	211: "timerfd_gettime",
	212: "epoll_wait",
	213: "epoll_ctl",
	214: "epoll_create1",
	220: "clone",
	221: "execve",
	233: "epoll_ctl",
	242: "accept4",
	260: "wait4",
	261: "prlimit64",
	264: "statfs",
	278: "getrandom",
	291: "statx",
	441: "epoll_pwait2",
}

func syscallName(nr uint32) string {
	if name, ok := syscallNames[nr]; ok {
		return name
	}
	return fmt.Sprintf("syscall_%d", nr)
}

type syscallCount struct {
	Nr    uint32 `json:"syscall_nr"`
	Name  string `json:"syscall_name"`
	Count uint64 `json:"count"`
}

// JSONOutput is the structure written when --output=json
type JSONOutput struct {
	PID       uint32         `json:"pid"`
	ElapsedS  int            `json:"elapsed_seconds"`
	Syscalls  []syscallCount `json:"syscalls"`
}

func readCounts(m *ebpf.Map) ([]syscallCount, error) {
	var counts []syscallCount
	iter := m.Iterate()
	var nr uint32
	var count uint64
	for iter.Next(&nr, &count) {
		counts = append(counts, syscallCount{
			Nr:    nr,
			Name:  syscallName(nr),
			Count: count,
		})
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("iterating syscall map: %w", err)
	}
	sort.Slice(counts, func(i, j int) bool {
		return counts[i].Count > counts[j].Count
	})
	return counts, nil
}

func printTable(counts []syscallCount, pid uint32, elapsed int) {
	fmt.Print("\033[2J\033[H")
	fmt.Printf("tracery count — PID %d — %ds elapsed\n", pid, elapsed)
	fmt.Println("─────────────────────────────────────")
	fmt.Printf("%-6s %-24s %s\n", "RANK", "SYSCALL", "COUNT")
	fmt.Println("─────────────────────────────────────")
	limit := 20
	if len(counts) < limit {
		limit = len(counts)
	}
	for i, c := range counts[:limit] {
		fmt.Printf("%-6d %-24s %d\n", i+1, c.Name, c.Count)
	}
	if len(counts) == 0 {
		fmt.Println("(no syscalls recorded yet...)")
	}
}

func printJSON(counts []syscallCount, pid uint32, elapsed int) error {
	out := JSONOutput{
		PID:      pid,
		ElapsedS: elapsed,
		Syscalls: counts,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

var countCmd = &cobra.Command{
	Use:   "count",
	Short: "Count syscalls for a target process",
	Long: `Count syscalls made by a process and display a live ranked table.

Examples:
  tracery count --pid 1234
  tracery count --pid 1234 --output json
  tracery count --pid 1234 --interval 2`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		output, _ := cmd.Flags().GetString("output")
		interval, _ := cmd.Flags().GetInt("interval")

		if pid == 0 {
			return fmt.Errorf("--pid is required (e.g. tracery count --pid 1234)")
		}
		if output != "table" && output != "json" {
			return fmt.Errorf("--output must be 'table' or 'json', got %q", output)
		}

		log.Info().
			Uint32("pid", pid).
			Str("output", output).
			Int("interval_s", interval).
			Msg("starting syscall counter")

		tracer, err := bpfloader.NewTracer("bpf/syscall_counter.bpf.o", pid)
		if err != nil {
			// %w wraps the error — caller can inspect the cause
			return fmt.Errorf("failed to start tracer: %w", err)
		}
		defer tracer.Close()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		elapsed := 0

		for {
			select {
			case <-sig:
				log.Info().Msg("received signal — shutting down")
				return nil

			case <-ticker.C:
				elapsed += interval
				counts, err := readCounts(tracer.CountsMap)
				if err != nil {
					// Log but don't crash — next tick might succeed
					log.Error().Err(err).Msg("failed to read syscall counts")
					continue
				}

				switch output {
				case "json":
					if err := printJSON(counts, pid, elapsed); err != nil {
						log.Error().Err(err).Msg("failed to write JSON output")
					}
				default:
					printTable(counts, pid, elapsed)
				}
			}
		}
	},
}

func init() {
	countCmd.Flags().Uint32("pid", 0, "PID of process to trace (required)")
	countCmd.Flags().String("output", "table",
		"output format: table or json")
	countCmd.Flags().Int("interval", 1,
		"how often to refresh the table in seconds")
}