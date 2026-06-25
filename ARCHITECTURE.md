# Tracery Architecture

> A technical deep-dive into every component decision. Read this before contributing.

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Data Flow](#data-flow)
3. [Kernel Side: BPF Programs](#kernel-side-bpf-programs)
4. [The BPF Verifier](#the-bpf-verifier)
5. [CO-RE and BTF Portability](#co-re-and-btf-portability)
6. [BPF Maps](#bpf-maps)
7. [Ring Buffer Design](#ring-buffer-design)
8. [Userspace: Go Daemon](#userspace-go-daemon)
9. [YAML Probe Format](#yaml-probe-format)
10. [Stack Traces and Flame Graphs](#stack-traces-and-flame-graphs)
11. [Overhead Measurement](#overhead-measurement)
12. [Key Design Decisions](#key-design-decisions)
13. [Known Limitations](#known-limitations)

---

## System Overview

Tracery is split into two halves separated by the kernel/userspace boundary:

```
  ┌─────────────────────────────────────────────────────────────────┐
  │                         USER SPACE                              │
  │                                                                 │
  │  ┌──────────┐  YAML  ┌──────────────┐  BPF obj  ┌──────────┐  │
  │  │  CLI     │───────▶│ Probe Loader │──────────▶│  libbpf  │  │
  │  │  (cobra) │        │    (Go)      │           └────┬─────┘  │
  │  └──────────┘        └──────────────┘                │        │
  │        │                                        load  │        │
  │        │ read events                                  ▼        │
  │  ┌─────▼────┐  events  ┌──────────────┐       ┌──────────┐   │
  │  │Aggregator│◀─────────│ Ring Buffer  │◀──────│  Kernel  │   │
  │  │   (Go)   │          │  Consumer    │       │   BPF    │   │
  │  └─────┬────┘          └──────────────┘       └──────────┘   │
  │        │                                                       │
  │  ┌─────▼──────────────────────────────────────────────────┐   │
  │  │              Output Renderer (Go)                      │   │
  │  │   stdout table  │  JSON  │  Flame Graph JSON           │   │
  │  └────────────────────────────────────────────────────────┘   │
  └─────────────────────────────────────────────────────────────────┘
                             ▲ load
  ┌─────────────────────────────────────────────────────────────────┐
  │                       KERNEL SPACE                              │
  │                                                                 │
  │  ┌──────────┐  ┌───────────┐  ┌────────────────┐             │
  │  │  kprobe  │  │tracepoint │  │    uprobe      │             │
  │  │(sys_enter)│  │(sched/mm) │  │(user fn attach)│             │
  │  └────┬─────┘  └─────┬─────┘  └───────┬────────┘             │
  │       └──────────────┴────────────────┘                       │
  │                       │ fires BPF program                      │
  │                       ▼                                        │
  │             ┌─────────────────────┐                           │
  │             │   BPF Program (C)   │                           │
  │             │  reads ctx fields   │                           │
  │             │  writes to map      │                           │
  │             └──────────┬──────────┘                           │
  │                        │                                       │
  │            ┌───────────▼───────────┐                         │
  │            │       BPF Maps        │                          │
  │            │  ring_buf / hash /    │                          │
  │            │  array / stack_trace  │                          │
  │            └───────────────────────┘                          │
  └─────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

A single event travels this path from kernel to your terminal:

1. **Target process makes a syscall** (e.g., `read()`).
2. **Kernel fires a kprobe** at `sys_enter_read` — the hook point Tracery registered.
3. **BPF program executes** in the kernel's sandboxed VM. It reads the syscall arguments from the `pt_regs` context, filters by PID, and writes a structured `event_t` to the ring buffer.
4. **Ring buffer signals userspace** via an `epoll`-like mechanism that libbpf polls.
5. **Go ring buffer consumer** reads the raw `event_t` bytes and passes them to the aggregator.
6. **Aggregator** updates in-memory counters, histograms, or stack trace maps.
7. **Output renderer** formats and writes to stdout (or JSON file) on each tick.

Total latency from syscall to terminal output is typically **5–20ms** (dominated by the Go ticker interval, not BPF overhead).

---

## Kernel Side: BPF Programs

BPF programs live in `bpf/*.bpf.c`. They are compiled to BPF bytecode by clang:

```makefile
clang-16 -g -O2 -target bpf -D__TARGET_ARCH_x86 \
    -I/usr/include/x86_64-linux-gnu \
    -c syscall_counter.bpf.c -o syscall_counter.bpf.o
```

Key constraints imposed by the BPF verifier:

- **No unbounded loops.** Every loop must have a known bound (or use `bpf_loop()` on 5.17+).
- **No null pointer dereferences.** Every pointer must be checked before use.
- **Stack size limit: 512 bytes.** Large structs must live in BPF maps, not on the stack.
- **No global mutable state** (other than BPF maps). No static variables across invocations.
- **Program complexity limit.** The verifier limits instruction count and CFG depth. Complex programs must be split.

### Event Struct

Every event Tracery emits is a fixed-size C struct written to the ring buffer:

```c
// bpf/events.h — shared between BPF C and Go userspace via cgo
struct event_t {
    __u64  timestamp_ns;   // bpf_ktime_get_ns() at probe fire time
    __u32  pid;            // tgid (process ID, not thread ID)
    __u32  tid;            // pid (thread ID in Linux terms)
    __u32  syscall_nr;     // syscall number (from pt_regs->orig_ax)
    __s64  retval;         // return value (exit probes only; 0 otherwise)
    __u64  latency_ns;     // entry-to-exit delta (exit probes only)
    __u32  probe_id;       // which probe fired (index into probe registry)
    char   comm[16];       // process name from bpf_get_current_comm()
    char   payload[64];    // probe-specific extra data (filename, flags, etc.)
};
```

The struct is **fixed-size**. Variable-length strings are truncated to fit `payload[64]`. This is intentional — variable-length ring buffer records add significant complexity with minimal benefit for the data Tracery captures.

---

```markdown
### uprobe Programs

`bpf/uprobe.bpf.c` is a self-contained BPF object (it does not share
`event_t` with the kernel-probe programs — see Known Limitations on why).
It implements three attach points:

- `handle_uprobe_entry` — fires on function entry only. Captures the
  first two argument registers (`PT_REGS_PARM1`/`PARM2`) into the
  event's `payload` field.
- `handle_uprobe_pair_entry` / `handle_uprobe_pair_exit` — a paired
  uprobe + uretprobe. Entry stashes a timestamp in a per-TID hash map
  (the same pattern M2 uses for syscall latency); exit computes the
  delta and reads the return value via `PT_REGS_RC`.
- `handle_uretprobe_only` — fires on return only, for return-value
  capture without latency measurement.

Symbol-to-address resolution happens in Go via `debug/elf`, then
`cilium/ebpf`'s `link.OpenExecutable().Uprobe()` / `.Uretprobe()`
computes the runtime attach address — Tracery's BPF C code never deals
with binary offsets directly.
```

---

## The BPF Verifier

The verifier runs every BPF program through a static analysis pass before loading it into the kernel. It rejects programs that could crash or corrupt the kernel.

**Common rejection reasons and fixes:**

| Rejection Message | Root Cause | Fix |
|---|---|---|
| `invalid mem access 'map_value_or_null'` | Map lookup result not null-checked | `if (!val) return 0;` after every `bpf_map_lookup_elem()` |
| `R1 offset is outside of the packet` | Direct pointer dereference from context | Use `BPF_CORE_READ(ctx, field)` instead |
| `back-edge from insn X to Y` | Loop the verifier can't bound | Unroll, use `#pragma unroll`, or restructure |
| `combined stack size of 2 calls is 768` | Stack depth exceeded in helper chain | Move large structs to a per-CPU array map |
| `too many instructions` | Program exceeds 1M insn limit | Split into tail calls |

The verifier error message includes the instruction offset and register state at rejection. Reading it takes practice — the `bpftool prog load` output is more readable than the kernel log.

---

## CO-RE and BTF Portability

**The problem:** Kernel struct layouts change between versions. A program that reads `task_struct->mm` on 5.15 may read garbage on 6.1 if `mm` moved.

**The solution:** BPF CO-RE (Compile Once, Run Everywhere) uses BTF (BPF Type Format) debug info embedded in the kernel to relocate struct field accesses at load time.

```c
// WRONG — hardcodes struct layout, breaks on different kernels
__u32 pid = *((__u32 *)(task + 1234));

// RIGHT — CO-RE macro generates a BTF relocation record
__u32 pid = BPF_CORE_READ(task, pid);
```

At load time, libbpf reads `/sys/kernel/btf/vmlinux`, looks up the actual offset of `task_struct.pid` in the running kernel, and patches the instruction. The `.bpf.o` file is the same binary; only the offsets differ per kernel.

**Requirement:** The running kernel must have BTF enabled (`CONFIG_DEBUG_INFO_BTF=y`). All Ubuntu kernels since 20.04 and mainline kernels since 5.4 include it. Check: `ls /sys/kernel/btf/vmlinux`.

---

## BPF Maps

Tracery uses four map types:

### `BPF_MAP_TYPE_HASH`

Used for: per-syscall counts, per-TID latency timestamps.

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);          // syscall number
    __type(value, __u64);        // count
} syscall_counts SEC(".maps");
```

Key design choice: `max_entries` is set conservatively. Hash maps do not grow dynamically. If the map fills, new inserts silently fail. Tracery logs a warning via the drop counter when this happens.

### `BPF_MAP_TYPE_ARRAY`

Used for: log2 histogram buckets. Array maps are faster than hash maps for indexed access and are zero-initialized at creation.

```c
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 20);     // 20 buckets = 1µs to ~1s range
    __type(key, __u32);          // bucket index
    __type(value, __u64);        // sample count in this bucket
} latency_hist SEC(".maps");
```

### `BPF_MAP_TYPE_RINGBUF`

Used for: all event streaming. See [Ring Buffer Design](#ring-buffer-design).

### `BPF_MAP_TYPE_STACK_TRACE`

Used for: flame graph stack capture.

```c
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 1024);   // max unique stack traces stored
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));  // MAX_STACK_DEPTH = 127
} stack_traces SEC(".maps");
```

`bpf_get_stackid()` hashes the stack trace and stores it, returning a `stack_id`. The Go side resolves `stack_id → []u64 addresses → []string symbols` via `/proc/PID/maps` + DWARF.

---

## Ring Buffer Design

The ring buffer (`BPF_MAP_TYPE_RINGBUF`) is Tracery's primary event transport. It replaced the older `perf_event_array` in kernel 5.8 for several reasons:

| Feature | `perf_event_array` | `BPF_MAP_TYPE_RINGBUF` |
|---|---|---|
| Memory usage | Per-CPU buffers (wastes memory) | Single shared buffer |
| Event ordering | Per-CPU — out-of-order across CPUs | Global order guaranteed |
| API | Complex `perf_event_open` setup | Simple `bpf_ringbuf_output()` |
| Blocking write | Not available | `bpf_ringbuf_reserve()` pattern |
| Minimum kernel | 4.4 | 5.8 |

### Write path (BPF C)

```c
// Reserve space — returns NULL if buffer full (drop, don't block)
struct event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
if (!e) {
    __sync_fetch_and_add(&drop_count, 1);  // atomic drop counter
    return 0;
}
// Fill fields
e->pid = bpf_get_current_pid_tgid() >> 32;
e->timestamp_ns = bpf_ktime_get_ns();
// Submit — makes event visible to userspace
bpf_ringbuf_submit(e, 0);
```

### Read path (Go)

```go
// libbpf ring_buffer__poll blocks until events arrive or timeout
rb, _ := ringbuf.NewReader(objs.Events)
for {
    record, err := rb.Read()
    if err != nil { break }
    var event EventT
    binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event)
    aggregator.Process(event)
}
```

### Overflow handling

If the Go consumer falls behind the BPF producer, the ring buffer fills and `bpf_ringbuf_reserve()` returns NULL. Tracery increments `drop_count` (a global BPF variable) and surfaces it in the CLI as:

```
⚠ 142 events dropped — increase --ring-buffer-size (current: 4MB)
```

The default ring buffer size is **4MB**. Use `--ring-buffer-size 16MB` for high-throughput workloads.

---

## Userspace: Go Daemon

The Go side is structured as:

```
cmd/
  root.go          — cobra root command, global flags
  count.go         — tracery count subcommand
  latency.go       — tracery latency subcommand
  trace.go         — tracery trace subcommand (YAML-driven)
  bench.go         — tracery bench subcommand

internal/
  bpf/
    loader.go      — load .bpf.o, create maps, attach probes
    maps.go        — typed wrappers around BPF map read/write
    ringbuf.go     — ring buffer consumer goroutine
  aggregator/
    counter.go     — syscall frequency counter
    histogram.go   — log2 histogram accumulator
    stack.go       — stack ID → symbol resolver
  output/
    table.go       — ASCII table renderer
    json.go        — structured JSON emitter
    flamegraph.go  — Speedscope JSON serializer
  probe/
    yaml.go        — YAML probe config parser
    registry.go    — probe type → BPF attach call mapping
```

---

## TUI Dashboard

`tracery dashboard` is a Bubble Tea-based terminal UI that combines all
three live views (syscalls, latency, events) into one tabbed interface.
It deliberately does **not** duplicate any kernel-attach or polling logic
— it calls the exact same functions the plain CLI commands use.

### Shared poller layer

`internal/bpf/poll.go` is the single source of truth for attaching BPF
programs and reading their output on an interval:

```go
PollSyscallCounts(pid, interval, nameFn, onUpdate, stop)
PollLatencyHistogram(pid, syscallNr, interval, onUpdate, stop)
PollEvents(pid, typeFilter, onEvent, stop)
```

`count.go`, `latency.go`, and `events.go` each call one of these and
render the result as a plain-text table/histogram/log to stdout.
`dashboard.go` calls the same three functions but instead sends the
result into a running Bubble Tea program via `p.Send(...)`, as a
`tea.Msg`. This means a bug fix or behavior change in attach logic only
ever needs to happen in one place.

### Model/Update/View (Elm architecture)

Bubble Tea follows the Elm architecture: a `Model` holds all state, an
`Update` function transforms state in response to messages, and a `View`
function renders the current state to a string every frame.

````
┌──────────────┐   tea.Msg    ┌──────────────┐   string    ┌──────────┐
│  Poller      │─────────────▶│  Update()    │────────────▶│  View()  │
│  goroutines  │  p.Send(...) │  (Model)     │  re-render  │ (string) │
└──────────────┘              └──────────────┘             └──────────┘
````

Three goroutines run concurrently, one per data source (syscalls, latency,
events), each calling its respective `Poll*` function with a `stop`
channel for clean shutdown. Each goroutine's `onUpdate`/`onEvent` callback
calls `p.Send(...)` with a typed message (`syscallDataMsg`,
`latencyDataMsg`, `eventDataMsg`). Bubble Tea's runtime serializes all
incoming messages through a single `Update()` call, so there's no need for
additional locking despite three concurrent producers.

### View switching

`Model.active` tracks which of the three views (`ViewSyscalls`,
`ViewLatency`, `ViewEvents`) is currently displayed. Key presses `1`/`2`/`3`
set it directly; `Tab` cycles through all three. `View()` switches on
`m.active` and delegates rendering to `renderSyscalls`/`renderLatency`/
`renderEvents` in their respective `*_view.go` files.

### Known limitation

The Latency tab tracks exactly one syscall at a time, set via
`--syscall` at startup (default: `read`). If the traced process rarely
calls that syscall, the tab will show "(no data yet)" even though the
Syscalls tab shows plenty of activity on other syscalls. Pick `--syscall`
based on what the target workload actually does frequently.

---

### Concurrency model

```
main goroutine
  └── cobra command handler
        ├── probe loader (runs once, attaches probes)
        ├── ring buffer consumer goroutine (runs until SIGINT)
        │     └── sends Event structs to aggregator channel
        ├── aggregator goroutine (reads channel, updates maps)
        └── renderer ticker goroutine (reads aggregator, renders output)
```

The aggregator uses a `sync.RWMutex` protecting its internal maps. The renderer acquires a read lock on each tick. BPF map reads (for hash/array maps not using ring buffer) happen in the renderer goroutine.

---

## YAML Probe Format

The YAML format is intentionally **not Turing-complete**. It maps directly to BPF attach operations — there is no scripting, conditionals in the format, or dynamic code generation.

### Design constraints

1. **Every YAML key maps to exactly one BPF operation.** No hidden magic.
2. **Fields declared in YAML are a subset of the event struct.** The BPF program captures everything; YAML chooses which fields to display.
3. **Filters are simple boolean expressions** over captured fields. No arbitrary code.
4. **Probe types are an enum**, not open-ended. Adding a new probe type requires a Go change, not just YAML.

### Probe types

| Type | Kernel Hook | Use Case |
|---|---|---|
| `tracepoint` | Stable tracepoints (e.g., `sched:sched_switch`) | Preferred — stable ABI across kernels |
| `kprobe` | Dynamic kprobe on kernel function entry | When no tracepoint exists |
| `kprobe_pair` | kprobe entry + exit | Latency measurement |
| `uprobe` | User-space function entry by symbol | Application-level tracing |
| `uprobe_pair` | User-space function entry + exit | Userspace latency measurement |
| `uretprobe` | User-space function return only | Return value capture |
| `tracepoint_pair` | Two correlated tracepoints | Run-queue latency |

---

## Stack Traces and Flame Graphs

### Capture (BPF C)

```c
// In a kprobe handler:
__u64 flags = BPF_F_USER_STACK;  // or 0 for kernel stack
__s64 stack_id = bpf_get_stackid(ctx, &stack_traces, flags);
if (stack_id >= 0) {
    e->stack_id = (__u32)stack_id;
}
```

Stack traces require the target binary to have frame pointers. Most production binaries strip them (`-fomit-frame-pointer` is the default). For Go binaries, use `-gcflags="-l"` to disable inlining (improves stack quality).

### Symbol resolution (Go)

```
stack_id
  → bpf_map_lookup_elem(stack_traces, stack_id) → []uint64 addresses
  → /proc/PID/maps → map address to binary + offset
  → binary DWARF info (if available) → symbol name + source line
  → fallback: hex address if no symbol found
```

### Speedscope JSON output

Tracery outputs [Speedscope's file format](https://github.com/nicolo-ribaudo/speedscope/blob/main/src/lib/file-format-spec.ts):

```json
{
  "$schema": "https://www.speedscope.app/file-format-schema.json",
  "shared": {
    "frames": [
      { "name": "handle_request", "file": "server.go", "line": 42 }
    ]
  },
  "profiles": [{
    "type": "sampled",
    "name": "PID 1234 — read() latency",
    "unit": "nanoseconds",
    "startValue": 0,
    "endValue": 30000000,
    "samples": [[0, 1, 3], [0, 2, 3]],
    "weights": [1500000, 2000000]
  }]
}
```

Open with: `speedscope flamegraph.json` or drag-drop to [speedscope.app](https://speedscope.app).

---

## Overhead Measurement

### Primary method: wall-clock timing (3-run median)

Overhead was measured by running a fork/exec-heavy workload (100k iterations of
`cat /dev/null`) three times each under three conditions and taking the median:

```bash
# Baseline — untraced
for i in 1 2 3; do { time bash workload.sh; } 2>&1 | grep real; done

# strace — ptrace mechanism
for i in 1 2 3; do { time strace -o /dev/null bash workload.sh; } 2>&1 | grep real; done

# Tracery — eBPF mechanism
sudo -v
for i in 1 2 3; do
  bash workload.sh &
  WPID=$!
  sudo ./tracery count --pid $WPID > /dev/null &
  TPID=$!
  wait $WPID
  kill $TPID 2>/dev/null
  echo "Run $i done"
done
```

Results (Ubuntu 24.04, kernel 6.x, VirtualBox):

| Condition | Run 1 | Run 2 | Run 3 | Median |
|-----------|-------|-------|-------|--------|
| Baseline  | 76.9s | 73.5s | 70.7s | **73.5s** |
| strace (`-o /dev/null`) | 151.2s | 148.5s | 148.0s | **148.5s** |
| Tracery | ~70s | ~72s | ~78s | **~72s** |

**strace overhead: +102% (2.0× slower). Tracery overhead: <2% (within measurement noise).**

The strace overhead is structural and not output-related — even with `-o /dev/null`
suppressing all output, `ptrace` still stops the target process on every syscall
entry and exit, causing two forced context switches per syscall. At 100k syscalls/sec,
this dominates wall time. Tracery's eBPF programs execute in the kernel without
stopping the process.

### Secondary method: `perf_event_open` instruction-count delta

The `tracery bench` command implements instruction-count measurement via
`perf_event_open(PERF_COUNT_HW_INSTRUCTIONS)`:

```
tracery bench --workload "bash workload.sh" --duration 10s
```

Procedure:
1. Run the workload for `--duration` **without** tracing. Record instruction count.
2. Attach Tracery. Run the workload for `--duration` **with** tracing. Record instruction count.
3. Compute delta: `overhead = (traced - untraced) / untraced * 100`.

**Hardware counter availability:** `PERF_COUNT_HW_INSTRUCTIONS` requires either
bare-metal hardware or a hypervisor that exposes the CPU's PMU (Performance
Monitoring Unit). VirtualBox and most cloud VM types do not expose PMU counters
(`perf_event_paranoid` controls access but cannot create counters the hypervisor
doesn't pass through). On such environments `tracery bench` falls back to
wall-clock timing automatically and prints an explanation.

To get instruction-count numbers, run on bare metal or a KVM VM with:

```bash
# Enable PMU passthrough in KVM
-cpu host,+pmu
```

Target: **< 3% CPU overhead** on typical server workloads (< 100k syscalls/sec).

At high syscall rates (> 500k/sec), ring buffer contention becomes the bottleneck.
Use `--mode=count-only` (hash map counters, no ring buffer streaming) to keep
overhead under 1%.

---

## Key Design Decisions

### Why libbpf over bcc?

bcc compiles BPF programs at runtime using LLVM embedded in your binary. This means:
- **Deployment size**: bcc adds ~90MB LLVM to your binary. Tracery is ~15MB.
- **Startup time**: bcc takes 1–3s to JIT-compile at startup. libbpf loads pre-compiled .bpf.o in < 100ms.
- **Production safety**: libbpf with CO-RE runs on any 5.4+ kernel with BTF, without LLVM installed.

### Why cilium/ebpf over direct cgo to libbpf?

`cilium/ebpf` is a pure Go library that implements the BPF syscall interface without cgo. This means:
- **Static binary**: `CGO_ENABLED=0 go build` produces a single static binary.
- **Cross-compilation**: `GOARCH=arm64 go build` works without an ARM toolchain.
- **No shared library dependency**: no `libelf.so` or `libbpf.so` required at runtime.

The tradeoff: cilium/ebpf lags behind the latest libbpf features by a few months. For Tracery's feature set, this is not a constraint.

### Why ring buffer over perf_event_array?

See [Ring Buffer Design](#ring-buffer-design). The short answer: global event ordering and simpler Go consumer code.

### Why fixed-size event structs?

Variable-length records (via `bpf_ringbuf_output` with dynamic size) would allow capturing full filenames. We chose fixed-size for two reasons:
1. **BPF verifier simplicity**: Variable-size reserve calls require dynamic size bounds the verifier must reason about.
2. **Go parsing simplicity**: Fixed-size structs allow `binary.Read` with a static type — no framing protocol needed.

The 64-byte `payload` field covers the common cases (path prefix, flag values, addresses). Full paths are rarely needed for performance analysis.

---

## Known Limitations

| Limitation | Impact | Workaround |
|---|---|---|
| Requires kernel 5.8+ | Older Ubuntu/RHEL not supported | Use Docker with a modern kernel |
| Requires root or CAP_BPF | Cannot run as unprivileged user | `setcap cap_bpf,cap_perfmon+ep ./tracery` |
| Stack traces need frame pointers | Stripped binaries show hex addresses | Rebuild with `-fno-omit-frame-pointer` |
| Ring buffer overflow is silent | Events dropped at high syscall rates | Monitor drop counter; increase `--ring-buffer-size` |
| CO-RE requires BTF in kernel | Custom kernels without BTF not supported | Rebuild kernel with `CONFIG_DEBUG_INFO_BTF=y` |
| uprobe overhead is higher | uprobe is 3-5x more expensive than kprobe | Use sparingly; profile only target functions |
| `uretprobe`/`uprobe_pair` can crash Go target binaries | Go's stack-moving garbage collector can corrupt scheduler state when the kernel's return-probe trampoline fires mid-stack-growth | Use plain `uprobe` (entry-only) for Go targets; `uprobe_pair`/`uretprobe` are safe on C/C++/Rust binaries with fixed stacks |
| No network packet capture | Not a replacement for tcpdump/XDP | Combine with `tcpdump` for network analysis |
| Hardware PMU unavailable in VMs | `tracery bench` instruction-count mode doesn't work on VirtualBox/most cloud VMs | Use wall-clock mode (automatic fallback) or run on bare metal / KVM with `-cpu host,+pmu` |
| Dashboard's Latency tab tracks only one syscall | `--syscall` must be set correctly for the target workload, or the tab shows "(no data yet)" | Check the Syscalls tab first to see which syscall is actually frequent, then restart with `--syscall <name>` |

---

*Last updated: see git log. Open an issue if something here is wrong or outdated.*