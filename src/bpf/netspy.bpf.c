#include "netspy.bpf.h"

SEC("xdp")
int xdp_dilih(struct xdp_md *ctx)
{
	struct perf_trace_event e = {};

	// perf event for entering xdp program
	e.timestamp = bpf_ktime_get_ns();
	e.type = TYPE_ENTER;
	e.processing_time_ns = 0;
	bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
	
	if (bpf_get_prandom_u32() % 2 == 0) {
		

		// perf event for dropping packet
		e.type = TYPE_DROP;
		__u64 ts = bpf_ktime_get_ns();
		e.processing_time_ns = ts - e.timestamp;
		e.timestamp = ts;
		bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));

		bpf_printk("dropping packet");
		return XDP_DROP;
	}

	// perf event for passing packet
	e.type = TYPE_PASS;
	__u64 ts = bpf_ktime_get_ns();
	e.processing_time_ns = ts - e.timestamp;
	e.timestamp = ts;

	bpf_perf_event_output(ctx, &output_map, BPF_F_CURRENT_CPU, &e, sizeof(e));
	bpf_printk("passing packet");

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";