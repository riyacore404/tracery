// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2024 Tracery Authors
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Packed to match Go's encoding/binary, which serializes fields tightly with
// no struct padding. Field order/sizes must match aggregator.EventT exactly.
struct uprobe_event_t {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 syscall_nr;   // unused for uprobes; kept for layout parity
    __s64 retval;
    __u64 latency_ns;
    __u32 probe_id;
    char  comm[16];
    char  payload[64];
} __attribute__((packed));

volatile const __u32 target_pid = 0;
volatile const __u32 this_probe_id = 0;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u64);
} entry_ts SEC(".maps");

volatile __u64 drop_count = 0;

static __always_inline int filter_pid(void)
{
    if (!target_pid)
        return 0;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return pid != target_pid;
}

static __always_inline struct uprobe_event_t *reserve_event(void)
{
    struct uprobe_event_t *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        __sync_fetch_and_add(&drop_count, 1);
        return NULL;
    }
    e->pid          = bpf_get_current_pid_tgid() >> 32;
    e->tid          = (__u32)bpf_get_current_pid_tgid();
    e->timestamp_ns = bpf_ktime_get_ns();
    e->probe_id     = this_probe_id;
    e->retval       = 0;
    e->latency_ns   = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

SEC("uprobe")
int handle_uprobe_entry(struct pt_regs *ctx)
{
    if (filter_pid())
        return 0;

    struct uprobe_event_t *e = reserve_event();
    if (!e)
        return 0;

    __u64 arg0 = PT_REGS_PARM1(ctx);
    __u64 arg1 = PT_REGS_PARM2(ctx);
    __builtin_memcpy(&e->payload[0], &arg0, sizeof(arg0));
    __builtin_memcpy(&e->payload[8], &arg1, sizeof(arg1));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe")
int handle_uprobe_pair_entry(struct pt_regs *ctx)
{
    if (filter_pid())
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 ts  = bpf_ktime_get_ns();
    bpf_map_update_elem(&entry_ts, &tid, &ts, BPF_ANY);
    return 0;
}

SEC("uretprobe")
int handle_uprobe_pair_exit(struct pt_regs *ctx)
{
    if (filter_pid())
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u64 *start = bpf_map_lookup_elem(&entry_ts, &tid);
    if (!start)
        return 0;

    __u64 latency = bpf_ktime_get_ns() - *start;
    bpf_map_delete_elem(&entry_ts, &tid);

    struct uprobe_event_t *e = reserve_event();
    if (!e)
        return 0;

    e->latency_ns = latency;
    e->retval     = PT_REGS_RC(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uretprobe")
int handle_uretprobe_only(struct pt_regs *ctx)
{
    if (filter_pid())
        return 0;

    struct uprobe_event_t *e = reserve_event();
    if (!e)
        return 0;

    e->retval = PT_REGS_RC(ctx);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";