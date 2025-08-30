#include "netspy.bpf.h"

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(__u32));
	__uint(max_entries, 1024);
} output_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, char[16]);
} pids SEC(".maps");

SEC("xdp")
int xdp_netspy(struct xdp_md *ctx)
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

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_sys_enter_execve(void *ctx)
{
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    
    char comm[16];
    bpf_get_current_comm(&comm, sizeof(comm));

    bpf_map_update_elem(&pids, &pid, comm, BPF_ANY);
    bpf_printk("EXECVE: pid=%d comm=%s", pid, comm);

    return 0;
}

char _license[] SEC("license") = "GPL";