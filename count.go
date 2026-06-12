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

// syscallNames maps syscall numbers to names for ARM64 (aarch64).
// Source: include/uapi/asm-generic/unistd.h + arch/arm64/include/asm/unistd.h
// ARM64 uses the generic syscall table — no arch-specific overrides.
var syscallNames = map[uint32]string{
	0:   "io_setup",
	1:   "io_destroy",
	2:   "io_submit",
	3:   "io_cancel",
	4:   "io_getevents",
	5:   "setxattr",
	6:   "lsetxattr",
	7:   "fsetxattr",
	8:   "getxattr",
	9:   "lgetxattr",
	10:  "fgetxattr",
	11:  "listxattr",
	12:  "llistxattr",
	13:  "flistxattr",
	14:  "removexattr",
	15:  "lremovexattr",
	16:  "fremovexattr",
	17:  "getcwd",
	18:  "lookup_dcookie",
	19:  "eventfd2",
	20:  "epoll_create1",
	21:  "epoll_ctl",
	22:  "epoll_pwait",
	23:  "dup",
	24:  "dup3",
	25:  "fcntl",
	26:  "inotify_init1",
	27:  "inotify_add_watch",
	28:  "inotify_rm_watch",
	29:  "ioctl",
	30:  "ioprio_set",
	31:  "ioprio_get",
	32:  "flock",
	33:  "mknodat",
	34:  "mkdirat",
	35:  "unlinkat",
	36:  "symlinkat",
	37:  "linkat",
	38:  "renameat",
	39:  "umount2",
	40:  "mount",
	41:  "pivot_root",
	42:  "nfsservctl",
	43:  "statfs",
	44:  "fstatfs",
	45:  "truncate",
	46:  "ftruncate",
	47:  "fallocate",
	48:  "faccessat",
	49:  "chdir",
	50:  "fchdir",
	51:  "chroot",
	52:  "fchmod",
	53:  "fchmodat",
	54:  "fchownat",
	55:  "fchown",
	56:  "openat",
	57:  "close",
	58:  "vhangup",
	59:  "pipe2",
	60:  "quotactl",
	61:  "getdents64",
	62:  "lseek",
	63:  "read",
	64:  "write",
	65:  "readv",
	66:  "writev",
	67:  "pread64",
	68:  "pwrite64",
	69:  "preadv",
	70:  "pwritev",
	71:  "sendfile",
	72:  "pselect6",
	73:  "ppoll",
	74:  "signalfd4",
	75:  "vmsplice",
	76:  "splice",
	77:  "tee",
	78:  "readlinkat",
	79:  "newfstatat",
	80:  "fstat",
	81:  "sync",
	82:  "fsync",
	83:  "fdatasync",
	84:  "sync_file_range",
	85:  "timerfd_create",
	86:  "timerfd_settime",
	87:  "timerfd_gettime",
	88:  "utimensat",
	89:  "acct",
	90:  "capget",
	91:  "capset",
	92:  "personality",
	93:  "exit",
	94:  "exit_group",
	95:  "waitid",
	96:  "set_tid_address",
	97:  "unshare",
	98:  "futex",
	99:  "set_robust_list",
	100: "get_robust_list",
	101: "nanosleep",
	102: "getitimer",
	103: "setitimer",
	104: "kexec_load",
	105: "init_module",
	106: "delete_module",
	107: "timer_create",
	108: "timer_gettime",
	109: "timer_getoverrun",
	110: "timer_settime",
	111: "timer_delete",
	112: "clock_settime",
	113: "clock_gettime",
	114: "clock_getres",
	115: "clock_nanosleep",
	116: "syslog",
	117: "ptrace",
	118: "sched_setparam",
	119: "sched_setscheduler",
	120: "sched_getscheduler",
	121: "sched_getparam",
	122: "sched_setaffinity",
	123: "sched_getaffinity",
	124: "sched_yield",
	125: "sched_get_priority_max",
	126: "sched_get_priority_min",
	127: "sched_rr_get_interval",
	128: "restart_syscall",
	129: "kill",
	130: "tkill",
	131: "tgkill",
	132: "sigaltstack",
	133: "rt_sigsuspend",
	134: "rt_sigaction",
	135: "rt_sigprocmask",
	136: "rt_sigpending",
	137: "rt_sigtimedwait",
	138: "rt_sigqueueinfo",
	139: "rt_sigreturn",
	140: "setpriority",
	141: "getpriority",
	142: "reboot",
	143: "setregid",
	144: "setgid",
	145: "setreuid",
	146: "setuid",
	147: "setresuid",
	148: "getresuid",
	149: "setresgid",
	150: "getresgid",
	151: "setfsuid",
	152: "setfsgid",
	153: "times",
	154: "setpgid",
	155: "getpgid",
	156: "getsid",
	157: "setsid",
	158: "getgroups",
	159: "setgroups",
	160: "uname",
	161: "sethostname",
	162: "setdomainname",
	163: "getrlimit",
	164: "setrlimit",
	165: "getrusage",
	166: "umask",
	167: "prctl",
	168: "getcpu",
	169: "gettimeofday",
	170: "settimeofday",
	171: "adjtimex",
	172: "getpid",
	173: "getppid",
	174: "getuid",
	175: "geteuid",
	176: "getgid",
	177: "getegid",
	178: "gettid",
	179: "sysinfo",
	180: "mq_open",
	181: "mq_unlink",
	182: "mq_timedsend",
	183: "mq_timedreceive",
	184: "mq_notify",
	185: "mq_getsetattr",
	186: "msgget",
	187: "msgctl",
	188: "msgrcv",
	189: "msgsnd",
	190: "semget",
	191: "semctl",
	192: "semtimedop",
	193: "semop",
	194: "shmget",
	195: "shmctl",
	196: "shmat",
	197: "shmdt",
	198: "socket",
	199: "socketpair",
	200: "bind",
	201: "listen",
	202: "accept",
	203: "connect",
	204: "getsockname",
	205: "getpeername",
	206: "sendto",
	207: "recvfrom",
	208: "setsockopt",
	209: "getsockopt",
	210: "shutdown",
	211: "sendmsg",
	212: "recvmsg",
	213: "readahead",
	214: "brk",
	215: "munmap",
	216: "mremap",
	217: "add_key",
	218: "request_key",
	219: "keyctl",
	220: "clone",
	221: "execve",
	222: "mmap",
	223: "fadvise64",
	224: "swapon",
	225: "swapoff",
	226: "mprotect",
	227: "msync",
	228: "mlock",
	229: "munlock",
	230: "mlockall",
	231: "munlockall",
	232: "mincore",
	233: "madvise",
	234: "remap_file_pages",
	235: "mbind",
	236: "get_mempolicy",
	237: "set_mempolicy",
	238: "migrate_pages",
	239: "move_pages",
	240: "rt_tgsigqueueinfo",
	241: "perf_event_open",
	242: "accept4",
	243: "recvmmsg",
	260: "wait4",
	261: "prlimit64",
	262: "fanotify_init",
	263: "fanotify_mark",
	264: "name_to_handle_at",
	265: "open_by_handle_at",
	266: "clock_adjtime",
	267: "syncfs",
	268: "setns",
	269: "sendmmsg",
	270: "process_vm_readv",
	271: "process_vm_writev",
	272: "kcmp",
	273: "finit_module",
	274: "sched_setattr",
	275: "sched_getattr",
	276: "renameat2",
	277: "seccomp",
	278: "getrandom",
	279: "memfd_create",
	280: "bpf",
	281: "execveat",
	282: "userfaultfd",
	283: "membarrier",
	284: "mlock2",
	285: "copy_file_range",
	286: "preadv2",
	287: "pwritev2",
	288: "pkey_mprotect",
	289: "pkey_alloc",
	290: "pkey_free",
	291: "statx",
	292: "io_pgetevents",
	293: "rseq",
	294: "kexec_file_load",
	424: "pidfd_send_signal",
	425: "io_uring_setup",
	426: "io_uring_enter",
	427: "io_uring_register",
	428: "open_tree",
	429: "move_mount",
	430: "fsopen",
	431: "fsconfig",
	432: "fsmount",
	433: "fspick",
	434: "pidfd_open",
	435: "clone3",
	436: "close_range",
	437: "openat2",
	438: "pidfd_getfd",
	439: "faccessat2",
	440: "process_madvise",
	441: "epoll_pwait2",
	442: "mount_setattr",
	443: "quotactl_fd",
	444: "landlock_create_ruleset",
	445: "landlock_add_rule",
	446: "landlock_restrict_self",
	448: "process_mrelease",
	449: "futex_waitv",
	450: "set_mempolicy_home_node",
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
	PID      uint32         `json:"pid"`
	ElapsedS int            `json:"elapsed_seconds"`
	Syscalls []syscallCount `json:"syscalls"`
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

// printCSV writes one CSV snapshot. header controls whether the header row is printed.
func printCSV(counts []syscallCount, pid uint32, elapsed int, header bool) {
	if header {
		fmt.Println("pid,elapsed_seconds,syscall_nr,syscall_name,count")
	}
	for _, c := range counts {
		fmt.Printf("%d,%d,%d,%s,%d\n", pid, elapsed, c.Nr, c.Name, c.Count)
	}
}

var countCmd = &cobra.Command{
	Use:   "count",
	Short: "Count syscalls for a target process",
	Long: `Count syscalls made by a process and display a live ranked table.

Examples:
  sudo tracery count --pid 1234
  sudo tracery count --pid 1234 --output json
  sudo tracery count --pid 1234 --output csv
  sudo tracery count --pid 1234 --interval 2`,

	RunE: func(cmd *cobra.Command, args []string) error {
		pid, _ := cmd.Flags().GetUint32("pid")
		output, _ := cmd.Flags().GetString("output")
		interval, _ := cmd.Flags().GetInt("interval")

		if pid == 0 {
			return fmt.Errorf("--pid is required (e.g. tracery count --pid 1234)")
		}
		if output != "table" && output != "json" && output != "csv" {
			return fmt.Errorf("--output must be 'table', 'json', or 'csv', got %q", output)
		}

		log.Info().
			Uint32("pid", pid).
			Str("output", output).
			Int("interval_s", interval).
			Msg("starting syscall counter")

		tracer, err := bpfloader.NewTracer("bpf/syscall_counter.bpf.o", pid)
		if err != nil {
			return fmt.Errorf("failed to start tracer: %w", err)
		}
		defer tracer.Close()

		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

		ticker := time.NewTicker(time.Duration(interval) * time.Second)
		defer ticker.Stop()

		elapsed := 0
		csvHeaderPrinted := false

		for {
			select {
			case <-sig:
				log.Info().Msg("received signal — shutting down")
				return nil

			case <-ticker.C:
				elapsed += interval
				counts, err := readCounts(tracer.CountsMap)
				if err != nil {
					log.Error().Err(err).Msg("failed to read syscall counts")
					continue
				}

				switch output {
				case "json":
					if err := printJSON(counts, pid, elapsed); err != nil {
						log.Error().Err(err).Msg("failed to write JSON output")
					}
				case "csv":
					printCSV(counts, pid, elapsed, !csvHeaderPrinted)
					csvHeaderPrinted = true
				default:
					printTable(counts, pid, elapsed)
				}
			}
		}
	},
}

func init() {
	countCmd.Flags().Uint32("pid", 0, "PID of process to trace (required)")
	countCmd.Flags().String("output", "table", "output format: table, json, or csv")
	countCmd.Flags().Int("interval", 1, "how often to refresh the table in seconds")
}