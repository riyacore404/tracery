## Documentation

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Component design, data flow, BPF internals |
| [CONTRIBUTING.md](CONTRIBUTING.md) | How to add probe types, submit PRs |
| [examples/](examples/) | Ready-to-use YAML probe configs |

# Tracery

> An eBPF-based Linux syscall and performance tracer built with C and Go.

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-GPL--2.0-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%205.8%2B-lightgrey.svg)](https://kernel.org)

Tracery attaches eBPF probes to running Linux processes and streams syscall
activity, latency measurements, memory events, and scheduler activity in
real time.

Unlike `strace`, Tracery does not stop the target process on every syscall.
Instrumentation runs inside the kernel through eBPF, enabling low-overhead
observability without code changes or restarts.

[![Demo]( https://asciinema.org/a/88dwSxe1okYYG4Ri.svg)]( https://asciinema.org/a/88dwSxe1okYYG4Ri)

---

## Quick Start
sudo bash <(curl -fsSL https://raw.githubusercontent.com/youruser/tracery/main/setup.sh)

---

## Features

- Live syscall frequency tracking
- Syscall latency histograms
- Memory event tracing (`mmap`, `munmap`, `brk`)
- Scheduler context-switch monitoring
- Structured JSON output
- Ring-buffer-based event streaming
- BPF CO-RE portability across Linux kernel versions

---

## Why Tracery?

| Tool | Mechanism | Overhead | Structured Output |
|--------|------------|------------|-------------------|
| strace | ptrace | High | No |
| perf | Sampling | Low | Limited |
| **Tracery** | **eBPF** | **Low** | **Yes** |

Traditional syscall tracing tools such as `strace` rely on `ptrace`,
which pauses the traced process on every syscall entry and exit.

Tracery instead executes small verified programs directly inside the Linux
kernel using eBPF. Events are aggregated in BPF maps and streamed to
userspace through ring buffers, avoiding repeated context switches.

---

## Commands

### tracery count

Live syscall frequency table.

```bash
sudo tracery count --pid 1234

sudo tracery count \
  --pid 1234 \
  --output json

sudo tracery count \
  --pid 1234 \
  --interval 3
```

Example output:

```text
SYSCALL        COUNT
---------------------
read           15234
write           8201
futex           4312
epoll_wait      2987
```

---

### tracery latency

Measure syscall execution latency.

```bash
sudo tracery latency --pid 1234 --syscall read

sudo tracery latency --pid 1234 --syscall write

sudo tracery latency --pid 1234 --syscall openat
```

Latency is measured using entry/exit probe pairs and
`bpf_ktime_get_ns()`.

Example histogram:

```text
1-2 us     | ######
2-4 us     | ###########
4-8 us     | #################
8-16 us    | ######
16-32 us   | ##
```

---

### tracery events

Stream kernel events in real time.

```bash
sudo tracery events --pid 1234 --type mem

sudo tracery events --pid 1234 --type sched

sudo tracery events --pid 1234 --type all
```

Supported event categories:

- Memory allocation events
- Memory mapping events
- Scheduler context switches

---

## Architecture

```text
+------------------------------------------------------------------+
|                          USER SPACE                              |
|                                                                  |
|  tracery CLI (Go + Cobra)                                        |
|          |                                                       |
|          v                                                       |
|  internal/bpf/loader.go                                          |
|          |                                                       |
|          v                                                       |
|  Ring Buffer Consumer                                            |
|          |                                                       |
|          v                                                       |
|  Output Renderer (table / JSON / event log)                      |
+------------------------------------------------------------------+
                     |
                     | cilium/ebpf
                     v
+------------------------------------------------------------------+
|                         KERNEL SPACE                             |
|                                                                  |
|  tracepoint/raw_syscalls/sys_enter                               |
|  tracepoint/raw_syscalls/sys_exit                                |
|  tracepoint/syscalls/sys_enter_mmap                              |
|  tracepoint/sched/sched_switch                                   |
|          |                                                       |
|          v                                                       |
|  eBPF Programs (C)                                               |
|          |                                                       |
|          v                                                       |
|  BPF Maps                                                        |
|   • Hash maps                                                    |
|   • Array maps                                                   |
|   • Ring buffers                                                 |
+------------------------------------------------------------------+
```

---

## Data Flow

### tracery count

1. eBPF program runs on syscall entry.
2. Counter is incremented in a hash map keyed by syscall ID.
3. Userspace periodically reads map contents.
4. Results are sorted and rendered.

### tracery latency

1. Syscall entry timestamp is stored in a hash map keyed by TID.
2. Syscall exit retrieves the timestamp.
3. Latency is calculated.
4. Appropriate histogram bucket is incremented.
5. Userspace renders histogram output.

### tracery events

1. Kernel events are written into a ring buffer.
2. Userspace consumes events.
3. Events are decoded into typed Go structures.
4. Output is streamed to the terminal.

---

## How It Works

### eBPF

eBPF is the Linux kernel's sandboxed virtual machine for running
instrumentation programs.

Programs are:

- Written in restricted C
- Compiled to BPF bytecode
- Verified by the kernel before loading

The verifier ensures programs:

- Cannot access arbitrary memory
- Cannot crash the kernel
- Cannot execute unbounded loops

---

### BPF CO-RE

Tracery uses Compile Once – Run Everywhere (CO-RE).

Kernel type information is provided through BTF
(BPF Type Format). During program loading, field offsets are relocated
to match the running kernel version.

This allows the same compiled eBPF object to run across multiple Linux
kernel releases without recompilation.

---

### Ring Buffers

Tracery uses `BPF_MAP_TYPE_RINGBUF` for event delivery.

Benefits:

- Lock-free communication
- Efficient kernel-to-userspace transfer
- Ordered event streaming
- Minimal synchronization overhead

---

## Installation

### Requirements

- Linux kernel 5.8+
- BTF enabled

```bash
ls /sys/kernel/btf/vmlinux
```

- Go 1.22+
- clang
- llvm
- bpftool
- Root privileges or CAP_BPF

### Build

```bash
git clone https://github.com/riyacore/tracery.git

cd tracery

make all

sudo ./tracery --help
```

---

## Project Structure

```text
tracery/
├── bpf/
│   ├── syscall_counter.bpf.c
│   ├── latency.bpf.c
│   ├── events.bpf.c
│   └── vmlinux.h
│
├── internal/
│   ├── bpf/
│   │   └── loader.go
│   │
│   └── logger/
│       └── logger.go
│
├── count.go
├── latency.go
├── events.go
├── main.go
└── Makefile
```

---

## Roadmap

### M4

- [ ] YAML-based probe definitions
- [ ] Speedscope flamegraph JSON export

### M5

- [ ] Benchmark command (`tracery bench`)
- [ ] GitHub Actions CI
- [ ] Goreleaser single-binary releases

### Future

- [ ] Interactive TUI dashboard (Bubble Tea)
- [ ] User-space function tracing (uprobes)
- [ ] Network event tracing
- [ ] Container-aware filtering

---

## License

GPL-2.0

Tracery is licensed under GPL-2.0, matching licensing requirements commonly
used by Linux kernel eBPF tooling.