
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

#define TYPE_ENTER  1
#define TYPE_DROP   2
#define TYPE_PASS   3

struct perf_trace_event {
	__u64 timestamp; // time elapsed since boot, excluding suspend time. see https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
	__u32 processing_time_ns;
	__u8 type;
};

struct connection_key {
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8 protocol;
};

struct connection_info {
    __u64 start_time;
    __u64 last_activity;
    __u64 bytes_sent;
    __u64 bytes_received;
    __u8 state; // 0=closed, 1=active, 2=established
    char process_comm[16];
    __u32 pid;
};

enum conn_state {
    CONN_CLOSED = 0,
    CONN_ACTIVE = 1,
    CONN_ESTABLISHED = 2
};
