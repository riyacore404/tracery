# Tracery Architecture

This document explains how Tracery is structured internally and how data
flows between the Linux kernel and userspace.

---

## High-Level Architecture

Tracery is split across the kernel/userspace boundary.

This is not merely a software design decision—it is a fundamental aspect
of how eBPF operates. eBPF programs execute inside the Linux kernel,
while rendering, CLI interaction, and data processing happen in userspace.

```text
+---------------------------+     +------------------------------+
|        KERNEL SPACE       |     |          USERSPACE           |
+---------------------------+     +------------------------------+
| eBPF Programs (C)         |     | Tracery CLI (Go + Cobra)     |
| Tracepoints              |     | internal/bpf/loader.go       |
| BPF Maps                 |     | Ring Buffer Consumer         |
| Kernel Verifier          |     | Output Renderer              |
+---------------------------+     +------------------------------+
              |                               ^
              |                               |
              +----------- BPF Maps ----------+
```

The primary communication mechanism between kernel space and userspace
is BPF maps.

eBPF programs write data into maps, while userspace components read,
aggregate, and display that information.

---

## eBPF Programs

Each Tracery command is backed by one or more eBPF programs compiled
from C source files into BPF object files.

| File | Purpose |
|--------|----------|
| `syscall_counter.bpf.c` | Syscall frequency counting |
| `latency.bpf.c` | Syscall latency measurement |
| `events.bpf.c` | Memory and scheduler event streaming |

Each program is attached to one or more kernel tracepoints.

Examples:

```text
syscall_counter.bpf.c
└── raw_syscalls/sys_enter

latency.bpf.c
├── raw_syscalls/sys_enter
└── raw_syscalls/sys_exit

events.bpf.c
├── syscalls/sys_enter_mmap
├── syscalls/sys_enter_munmap
├── syscalls/sys_enter_brk
└── sched/sched_switch
```

---

## eBPF Execution Constraints

eBPF programs execute inside the Linux kernel and therefore operate
under strict restrictions.

Programs:

- Cannot allocate dynamic memory
- Cannot access arbitrary kernel memory
- Cannot execute unbounded loops
- Must pass verifier analysis before loading

The kernel verifier performs static analysis to ensure programs are:

- Memory-safe
- Terminating
- Type-safe
- Non-crashing

Programs that fail verification are rejected before attachment.

---

## BPF Maps

Tracery uses three map types.

### BPF_MAP_TYPE_HASH

A kernel-resident key/value store.

Used for:

- Syscall counters
- Thread ID → timestamp storage

Examples:

```text
syscall_number -> count

thread_id -> start_timestamp
```

Characteristics:

- Average O(1) lookup
- Configurable maximum size
- Dynamic key insertion

---

### BPF_MAP_TYPE_ARRAY

A fixed-size indexed array.

Used for latency histogram buckets.

Example:

```text
bucket_index -> count
```

Characteristics:

- Constant-time access
- Lower overhead than hash maps
- Fixed size determined at creation

---

### BPF_MAP_TYPE_RINGBUF

A lock-free event transport mechanism between kernel space and userspace.

Used by:

```text
tracery events
```

Event flow:

```text
reserve event
      ↓
fill fields
      ↓
submit event
      ↓
userspace consumes
```

Typical eBPF sequence:

```c
event = bpf_ringbuf_reserve(...);
populate(event);
bpf_ringbuf_submit(event, 0);
```

Benefits:

- Low overhead
- Ordered event delivery
- Efficient kernel-to-userspace communication

---

## CO-RE and BTF

One challenge in eBPF development is kernel portability.

Kernel structure layouts change across versions.

For example:

```text
Kernel 5.15
task_struct.field -> offset 24

Kernel 6.1
task_struct.field -> offset 32
```

Hardcoding offsets would require recompiling for every kernel release.

Tracery avoids this using:

- BTF (BPF Type Format)
- CO-RE (Compile Once, Run Everywhere)

### BTF

BTF provides runtime type information for kernel structures.

Most modern Linux distributions expose BTF through:

```bash
/sys/kernel/btf/vmlinux
```

### CO-RE

CO-RE uses BTF metadata to relocate structure field accesses during
program loading.

This allows a single compiled BPF object to run across multiple kernel
versions without recompilation.

Typical access pattern:

```c
BPF_CORE_READ(task, pid);
```

The loader resolves the correct field offset automatically for the
running kernel.

---

## Userspace Components

The userspace side of Tracery is implemented in Go.

### Loader

`internal/bpf/loader.go` manages the complete eBPF lifecycle.

Loading sequence:

```text
LoadCollectionSpec()
        ↓
RewriteConstants()
        ↓
NewCollection()
        ↓
Verifier executes
        ↓
Tracepoint attachment
```

Typical workflow:

1. Parse the BPF object file
2. Inject runtime constants (such as target PID)
3. Load maps and programs into the kernel
4. Attach programs to tracepoints
5. Clean up resources on exit

---

## Command Execution Models

Different commands use different collection strategies.

### tracery count

```text
eBPF Hash Map
      ↓
Periodic Polling
      ↓
Sorted Output Table
```

A ticker periodically reads syscall counters from the map and renders
a ranked frequency table.

---

### tracery latency

```text
eBPF Histogram Array
          ↓
Periodic Polling
          ↓
ASCII Histogram
```

Histogram buckets are periodically read and rendered as latency
distributions.

---

### tracery events

```text
Ring Buffer
      ↓
Blocking Reader
      ↓
Event Stream
```

Unlike polling-based commands, the ring-buffer reader blocks until
events arrive.

This avoids unnecessary CPU usage when the system is idle.

---

## Design Decisions

### Why cilium/ebpf?

Tracery uses the Go package:

```text
github.com/cilium/ebpf
```

Advantages:

- Pure Go implementation
- No cgo dependency
- Native Go APIs
- Easier cross-compilation
- Efficient ring-buffer support

Compared with libbpf, this keeps the build process simpler and makes
distribution of a single Go binary easier.

---

### Why Cobra?

Cobra powers the command-line interface.

Advantages:

- Familiar command structure
- Automatic help generation
- Subcommand support
- Shared flag handling

The same framework is used by tools such as:

- kubectl
- Helm
- Docker (historically through Cobra components)

---

### Why Zerolog?

Zerolog provides structured logging with minimal allocations.

Benefits:

- Structured JSON output
- Fast performance
- Low memory overhead
- Easy integration with log aggregation systems

Example:

```json
{
  "level": "info",
  "pid": 1234,
  "syscall": "read"
}
```

---

### Why Log₂ Histograms?

Latency distributions often span multiple orders of magnitude.

Examples:

```text
100 ns
1 μs
10 μs
1 ms
10 ms
100 ms
```

Linear bucket sizing either:

- Wastes resolution on small values
- Loses detail on large values

Log₂ bucket sizing provides consistent visibility across the entire
latency range and makes performance outliers easier to identify.

Example bucket layout:

```text
0–1 μs
1–2 μs
2–4 μs
4–8 μs
8–16 μs
...
```

This approach is commonly used in production observability systems,
including eBPF-based performance analysis tools.

---