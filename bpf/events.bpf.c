// SPDX-License-Identifier: GPL-2.0
//
// events.bpf.c
//
// Streams memory and scheduler events to userspace via ring buffer.
// Uses BPF tracepoints — more stable than kprobes across kernel versions.
//
// Event types captured:
//   MEM_MMAP    — process mapped memory (mmap syscall)
//   MEM_MUNMAP  — process unmapped memory
//   MEM_BRK     — heap resize (malloc uses this internally)
//   SCHED_SWITCH — CPU context switch (process got preempted)

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

// -------------------------------------------------------
// Event type constants.
// Userspace uses these to decide how to display each event.
// -------------------------------------------------------
#define EVENT_MEM_MMAP     1
#define EVENT_MEM_MUNMAP   2
#define EVENT_MEM_BRK      3
#define EVENT_SCHED_SWITCH 4

// -------------------------------------------------------
// The event struct sent to userspace for every captured event.
// All event types share this struct — unused fields are zero.
// -------------------------------------------------------
struct event {
    u64  timestamp;     // nanoseconds since boot
    u32  pid;           // process ID
    u32  tid;           // thread ID
    u8   type;          // EVENT_* constant above
    char comm[16];      // process name

    // Memory event fields (valid for mmap/munmap/brk)
    u64  addr;          // memory address
    u64  size;          // size in bytes

    // Scheduler event fields (valid for sched_switch)
    u32  prev_pid;      // process being switched away from
    u32  next_pid;      // process being switched to
    char next_comm[16]; // name of incoming process
};

// Ring buffer — same pattern as mini 3
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 512KB — larger for event bursts
} events SEC(".maps");

// Filter: 0 = trace all PIDs
const volatile pid_t target_pid = 0;

// Filter flags — which event types to capture
const volatile u8 capture_mem   = 1; // capture memory events
const volatile u8 capture_sched = 1; // capture scheduler events

// -------------------------------------------------------
// Helper: fill common fields shared by all event types
// -------------------------------------------------------
static __always_inline void fill_common(struct event *e)
{
    u64 id    = bpf_get_current_pid_tgid();
    e->pid    = id >> 32;
    e->tid    = (u32)id;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

// -------------------------------------------------------
// PROBE: mmap
// Fires when a process calls mmap() to map memory.
// mmap is used for: loading libraries, allocating large
// memory blocks, memory-mapped files.
// -------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_mmap")
int trace_mmap(struct trace_event_raw_sys_enter *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;
    if (!capture_mem)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->type = EVENT_MEM_MMAP;
    // ctx->args[0] = addr hint, ctx->args[1] = length
    e->addr = (u64)ctx->args[0];
    e->size = (u64)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -------------------------------------------------------
// PROBE: munmap
// Fires when a process releases a memory mapping.
// -------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_munmap")
int trace_munmap(struct trace_event_raw_sys_enter *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;
    if (!capture_mem)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->type = EVENT_MEM_MUNMAP;
    e->addr = (u64)ctx->args[0];
    e->size = (u64)ctx->args[1];

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -------------------------------------------------------
// PROBE: brk
// Fires when a process resizes its heap.
// malloc() calls brk() internally when it needs more memory.
// -------------------------------------------------------
SEC("tracepoint/syscalls/sys_enter_brk")
int trace_brk(struct trace_event_raw_sys_enter *ctx)
{
    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (target_pid != 0 && pid != target_pid)
        return 0;
    if (!capture_mem)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    fill_common(e);
    e->type = EVENT_MEM_BRK;
    e->addr = (u64)ctx->args[0];
    e->size = 0; // brk doesn't have a size argument

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -------------------------------------------------------
// PROBE: sched_switch
// Fires every time the CPU switches from one process
// to another — a context switch.
//
// This is a tracepoint, not a syscall — it fires inside
// the scheduler, not at a syscall boundary.
//
// BPF_CORE_READ is required here because we're reading
// from kernel structs (task_struct) — direct dereference
// would be rejected by the verifier on some kernels.
// -------------------------------------------------------
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    if (!capture_sched)
        return 0;

    // Get the PID of the process being switched away from
    // BPF_CORE_READ safely reads the field using BTF relocations
    u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
    u32 next_pid = BPF_CORE_READ(ctx, next_pid);

    // Only capture if our target is involved in the switch
    if (target_pid != 0 &&
        prev_pid != (u32)target_pid &&
        next_pid != (u32)target_pid)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->type      = EVENT_SCHED_SWITCH;
    e->prev_pid  = prev_pid;
    e->next_pid  = next_pid;
    e->pid       = prev_pid;
    e->tid       = prev_pid;

    // Read prev_comm and next_comm safely via CO-RE
    bpf_probe_read_kernel_str(e->comm,
        sizeof(e->comm), ctx->prev_comm);
    bpf_probe_read_kernel_str(e->next_comm,
        sizeof(e->next_comm), ctx->next_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}