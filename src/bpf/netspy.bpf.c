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

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct connection_key);
    __type(value, struct connection_info);
} connections SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, struct connection_key);
    __type(value, __u64);
} connection_stats SEC(".maps");

SEC("kprobe/tcp_connect")
int BPF_KPROBE(tcp_connect, struct sock *sk)
{
    if (!sk) return 0;
    
    struct connection_key key = {};
    struct connection_info info = {};
    
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.protocol = IPPROTO_TCP;
    
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    info.pid = pid_tgid >> 32;
    bpf_get_current_comm(&info.process_comm, sizeof(info.process_comm));
    
    info.start_time = bpf_ktime_get_ns();
    info.last_activity = info.start_time;
    info.state = CONN_ACTIVE;
    
    bpf_map_update_elem(&connections, &key, &info, BPF_ANY);
    
    bpf_printk("CONNECTION START: %pI4:%d -> %pI4:%d, pid=%d, comm=%s",
               &key.saddr, key.sport, &key.daddr, key.dport, 
               info.pid, info.process_comm);
    
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(tcp_close, struct sock *sk)
{
    if (!sk) return 0;
    
    struct connection_key key = {};
    
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.protocol = IPPROTO_TCP;
    
    // Удаляем подключение из активных
    bpf_map_delete_elem(&connections, &key);
    
    bpf_printk("CONNECTION CLOSE: %pI4:%d -> %pI4:%d",
               &key.saddr, key.sport, &key.daddr, key.dport);
    
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    if (!sk) return 0;
    
    struct connection_key key = {};
    struct connection_info *info;
    
    key.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    key.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    key.sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    key.dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    key.protocol = IPPROTO_TCP;
    
    // Обновляем статистику отправленных данных
    info = bpf_map_lookup_elem(&connections, &key);
    if (info) {
        info->bytes_sent += size;
        info->last_activity = bpf_ktime_get_ns();
        info->state = CONN_ESTABLISHED;
    }
    
    return 0;
}

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