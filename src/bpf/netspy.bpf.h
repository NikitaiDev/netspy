#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define TYPE_ENTER  1
#define TYPE_DROP   2
#define TYPE_PASS   3

struct perf_trace_event {
	__u64 timestamp; // time elapsed since boot, excluding suspend time. see https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
	__u32 processing_time_ns;
	__u8 type;
};

