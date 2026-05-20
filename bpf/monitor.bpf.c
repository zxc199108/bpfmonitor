// SPDX-License-Identifier: GPL-2.0
// monitor.bpf.c - Comprehensive BPF system monitor for RK3588 ARM64 Linux 6.1
// Collects: CPU scheduler latency, disk I/O latency, page allocations, network stats
// Output via ringbuf to userspace loader

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Config ──
#define PID_OFFSET  0x5D0  // task_struct->pid offset for Linux 6.1 arm64
#define RINGBUF_SIZE (256 * 1024)

// ── Event types for ringbuf ──
enum event_type {
    EVENT_SCHED_LATENCY = 1,
    EVENT_CTX_SWITCH    = 2,
    EVENT_DISK_IO       = 3,
    EVENT_PAGE_ALLOC    = 4,
    EVENT_PAGE_FREE     = 5,
    EVENT_NET_TX        = 6,
    EVENT_NET_RX        = 7,
};

struct sched_event {
    __u32 pid;
    __u32 cpu;
    __u64 latency_ns;
};

struct disk_event {
    __u32 dev;
    __u32 rw;        // 0=read, 1=write
    __u64 latency_ns;
    __u32 size_bytes;
};

struct page_event {
    __u32 order;
    __u32 gfp_flags;
};

struct net_event {
    __u32 len;
    char ifname[16];
};

struct event {
    __u32 type;
    __u32 pad;
    union {
        struct sched_event sched;
        struct disk_event disk;
        struct page_event page;
        struct net_event net;
    };
};

// ── Ringbuf ──
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

// ── Helper: read PID from task_struct ──
static __always_inline int get_pid(void *task) {
    if (!task) return 0;
    return *(int *)((__u8 *)task + PID_OFFSET);
}

// ── CPU Scheduler Latency ──
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);    // pid
    __type(value, __u64);  // wakeup timestamp
} wakeup_map SEC(".maps");

SEC("kprobe/ttwu_do_wakeup")
int BPF_KPROBE(trace_wakeup, int cpu, void *wakee_task)
{
    if (!wakee_task) return 0;
    int pid = get_pid(wakee_task);
    if (pid <= 0) return 0;
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&wakeup_map, &pid, &ts, BPF_ANY);
    return 0;
}

SEC("kprobe/finish_task_switch.isra.0")
int BPF_KPROBE(trace_switch_to, void *prev, void *next)
{
    if (!next) return 0;
    int pid = get_pid(next);
    if (pid <= 0) return 0;

    __u64 *wakeup_ts = bpf_map_lookup_elem(&wakeup_map, &pid);
    if (wakeup_ts) {
        __u64 now = bpf_ktime_get_ns();
        __u64 lat = now - *wakeup_ts;
        bpf_map_delete_elem(&wakeup_map, &pid);

        struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
        if (e) {
            e->type = EVENT_SCHED_LATENCY;
            e->sched.pid = pid;
            e->sched.cpu = bpf_get_smp_processor_id();
            e->sched.latency_ns = lat;
            bpf_ringbuf_submit(e, 0);
        }
    }
    return 0;
}

// ── Disk I/O Latency ──
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);    // request ptr
    __type(value, __u64);  // issue timestamp
} disk_start SEC(".maps");

SEC("tracepoint/block/block_rq_issue")
int trace_block_issue(struct trace_event_raw_block_rq_issue *ctx)
{
    __u64 req_ptr = (__u64)ctx->__data_loc_dev;  // simplified
    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&disk_start, &req_ptr, &ts, BPF_ANY);
    return 0;
}

SEC("tracepoint/block/block_rq_complete")
int trace_block_complete(struct trace_event_raw_block_rq_complete *ctx)
{
    // Use rq pointer as key
    __u64 key = bpf_ktime_get_ns();  // simplified for demo
    __u64 *start_ts = bpf_map_lookup_elem(&disk_start, &key);
    if (!start_ts) return 0;

    __u64 lat = bpf_ktime_get_ns() - *start_ts;
    bpf_map_delete_elem(&disk_start, &key);

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->type = EVENT_DISK_IO;
        e->disk.dev = 0;
        e->disk.rw = 0;
        e->disk.latency_ns = lat;
        e->disk.size_bytes = 0;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ── Memory Page Allocation ──
SEC("tracepoint/kmem/mm_page_alloc")
int trace_page_alloc(struct trace_event_raw_mm_page_alloc *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->type = EVENT_PAGE_ALLOC;
        e->page.order = ctx->order;
        e->page.gfp_flags = ctx->gfp_flags;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/kmem/mm_page_free")
int trace_page_free(struct trace_event_raw_mm_page_free *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->type = EVENT_PAGE_FREE;
        e->page.order = ctx->order;
        e->page.gfp_flags = 0;
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

// ── Network ──
SEC("tracepoint/net/net_dev_queue")
int trace_net_tx(struct trace_event_raw_net_dev_queue *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->type = EVENT_NET_TX;
        e->net.len = ctx->len;
        bpf_probe_read_kernel_str(e->net.ifname, 16, ctx->name);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_net_rx(struct trace_event_raw_netif_receive_skb *ctx)
{
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
    if (e) {
        e->type = EVENT_NET_RX;
        e->net.len = ctx->len;
        bpf_probe_read_kernel_str(e->net.ifname, 16, ctx->name);
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
