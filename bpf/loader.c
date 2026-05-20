// SPDX-License-Identifier: GPL-2.0
// loader.c - Userspace BPF loader for monitor.bpf.o
// Reads ringbuf events and outputs JSON lines
//
// Build: make
// Usage: sudo ./loader

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

struct event {
    __u32 type;
    __u32 pad;
    union {
        struct {
            __u32 pid;
            __u32 cpu;
            __u64 latency_ns;
        } sched;
        struct {
            __u32 dev;
            __u32 rw;
            __u64 latency_ns;
            __u32 size_bytes;
        } disk;
        struct {
            __u32 order;
            __u32 gfp_flags;
        } page;
        struct {
            __u32 len;
            char ifname[16];
        } net;
    };
};

static volatile int running = 1;

static void sig_handler(int sig) { running = 0; }

static int handle_event(void *ctx, void *data, size_t len) {
    struct event *e = data;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    double t = ts.tv_sec + ts.tv_nsec / 1e9;

    switch (e->type) {
    case 1: // SCHED_LATENCY
        printf("{\"t\":%.3f,\"type\":\"sched\",\"pid\":%u,\"cpu\":%u,\"lat_ns\":%llu}\n",
               t, e->sched.pid, e->sched.cpu,
               (unsigned long long)e->sched.latency_ns);
        break;
    case 3: // DISK_IO
        printf("{\"t\":%.3f,\"type\":\"disk\",\"dev\":%u,\"rw\":%u,\"lat_ns\":%llu}\n",
               t, e->disk.dev, e->disk.rw,
               (unsigned long long)e->disk.latency_ns);
        break;
    case 4: // PAGE_ALLOC
        printf("{\"t\":%.3f,\"type\":\"page_alloc\",\"order\":%u}\n",
               t, e->page.order);
        break;
    case 5: // PAGE_FREE
        printf("{\"t\":%.3f,\"type\":\"page_free\",\"order\":%u}\n",
               t, e->page.order);
        break;
    case 6: // NET_TX
        printf("{\"t\":%.3f,\"type\":\"net_tx\",\"if\":\"%s\",\"len\":%u}\n",
               t, e->net.ifname, e->net.len);
        break;
    case 7: // NET_RX
        printf("{\"t\":%.3f,\"type\":\"net_rx\",\"if\":\"%s\",\"len\":%u}\n",
               t, e->net.ifname, e->net.len);
        break;
    }
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    int err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    const char *obj_path = "bpf/monitor.bpf.o";
    if (argc > 1) obj_path = argv[1];

    obj = bpf_object__open(obj_path);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", obj_path);
        return 1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find ringbuf map 'events'\n");
        bpf_object__close(obj);
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    // Attach programs
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        bpf_program__attach(prog);
    }

    fprintf(stderr, "[loader] BPF monitor running. Press Ctrl+C to stop.\n");

    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "ring_buffer__poll error: %d\n", err);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    fprintf(stderr, "[loader] Stopped.\n");
    return 0;
}
