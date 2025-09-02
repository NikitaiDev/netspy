#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "netspy.skel.h"
#include <time.h>

#define TYPE_ENTER  1
#define TYPE_DROP   2
#define TYPE_PASS   3

struct perf_trace_event {
	__u64 timestamp; // time elapsed since boot, excluding suspend time. see https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
	__u32 processing_time_ns;
	__u8 type;
};

struct bpf_link *tracepoint_sys_enter_execve;
static volatile bool exiting = false;

static void sig_handler(int sig);
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
static void handle_event(void *ctx, int cpu, void *data, __u32 size);
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt);
static void print_pids_map(struct netspy_bpf *skel);