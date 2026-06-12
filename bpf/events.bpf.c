// SPDX-License-Identifier: GPL-2.0
//
// events.bpf.c
//
// Streams memory and scheduler events to userspace via ring buffer.
//
// ARM64 NOTE: syscall-specific tracepoints like sys_enter_mmap do NOT
// exist on ARM64 (aarch64). ARM64 uses the generic syscall path.
// We attach to raw_syscalls/sys_enter and filter by syscall number.
//
// ARM64 syscall numbers used here:
//   mmap   = 222
//   munmap = 215
//   brk    = 214
//
// Event types:
//   1 = MEM_MMAP
//   2 = MEM_MUNMAP
//   3 = MEM_BRK
//   4 = SCHED_SWITCH

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define EVENT_MEM_MMAP     1
#define EVENT_MEM_MUNMAP   2
#define EVENT_MEM_BRK      3
#define EVENT_SCHED_SWITCH 4

// ARM64 syscall numbers for memory operations
#define NR_MMAP   222
#define NR_MUNMAP 215
#define NR_BRK    214

// -------------------------------------------------------
// Event struct — must match kernelEvent in events.go exactly.
//
// Layout on ARM64 (8-byte alignment rules):
//   timestamp  u64   offset 0
//   pid        u32   offset 8
//   tid        u32   offset 12
//   type       u8    offset 16
//   comm[16]   char  offset 17  (17 bytes so far)
//   _pad[7]    u8    offset 33  (pad to 40 = next 8-byte boundary)
//   addr       u64   offset 40
//   size       u64   offset 48
//   prev_pid   u32   offset 56
//   next_pid   u32   offset 60
//   next_comm  char  offset 64
//   total size: 80 bytes
// -------------------------------------------------------
struct event {
    u64  timestamp;
    u32  pid;
    u32  tid;
    u8   type;
    char comm[16];
    u8   _pad[7];       // explicit padding to align addr to 8 bytes
    u64  addr;
    u64  size;
    u32  prev_pid;
    u32  next_pid;
    char next_comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024);
} events SEC(".maps");

const volatile pid_t target_pid    = 0;
const volatile u8    capture_mem   = 1;
const volatile u8    capture_sched = 1;

static __always_inline void fill_common(struct event *e)
{
    u64 id       = bpf_get_current_pid_tgid();
    e->pid       = id >> 32;
    e->tid       = (u32)id;
    e->timestamp = bpf_ktime_get_ns();
    bpf_get_current_comm(e->comm, sizeof(e->comm));
}

// -------------------------------------------------------
// Single sys_enter probe handles mmap/munmap/brk on ARM64.
// Syscall-specific tracepoints don't exist on this arch.
// -------------------------------------------------------
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_mem_syscalls(struct trace_event_raw_sys_enter *ctx)
{
    if (!capture_mem)
        return 0;

    u64 id  = bpf_get_current_pid_tgid();
    u32 pid = id >> 32;

    if (target_pid != 0 && pid != (u32)target_pid)
        return 0;

    u32 nr = (u32)ctx->id;
    if (nr != NR_MMAP && nr != NR_MUNMAP && nr != NR_BRK)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    fill_common(e);

    switch (nr) {
    case NR_MMAP:
        e->type = EVENT_MEM_MMAP;
        e->addr = (u64)ctx->args[0];
        e->size = (u64)ctx->args[1];
        break;
    case NR_MUNMAP:
        e->type = EVENT_MEM_MUNMAP;
        e->addr = (u64)ctx->args[0];
        e->size = (u64)ctx->args[1];
        break;
    case NR_BRK:
        e->type = EVENT_MEM_BRK;
        e->addr = (u64)ctx->args[0];
        e->size = 0;
        break;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

// -------------------------------------------------------
// Scheduler context switch — stable tracepoint on all arches
// -------------------------------------------------------
SEC("tracepoint/sched/sched_switch")
int trace_sched_switch(struct trace_event_raw_sched_switch *ctx)
{
    if (!capture_sched)
        return 0;

    u32 prev_pid = BPF_CORE_READ(ctx, prev_pid);
    u32 next_pid = BPF_CORE_READ(ctx, next_pid);

    if (target_pid != 0 &&
        prev_pid != (u32)target_pid &&
        next_pid != (u32)target_pid)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->type      = EVENT_SCHED_SWITCH;
    e->prev_pid  = prev_pid;
    e->next_pid  = next_pid;
    e->pid       = prev_pid;
    e->tid       = prev_pid;
    e->addr      = 0;
    e->size      = 0;

    bpf_probe_read_kernel_str(e->comm,
        sizeof(e->comm), ctx->prev_comm);
    bpf_probe_read_kernel_str(e->next_comm,
        sizeof(e->next_comm), ctx->next_comm);

    bpf_ringbuf_submit(e, 0);
    return 0;
}