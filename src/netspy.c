#include "netspy.h"

int main(int argc, char **argv) {
    struct netspy_bpf *skel = NULL;
    struct perf_buffer *pb = NULL;
    int err, ifindex;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    libbpf_set_print(libbpf_print_fn);

    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index: %s\n", strerror(errno));
        return 1;
    }

    skel = netspy_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = netspy_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %d\n", err);
        goto cleanup;
    }
    skel->links.tcp_connect = bpf_program__attach(skel->progs.tcp_connect);
    if (!skel->links.tcp_connect) {
        fprintf(stderr, "Failed to attach tcp_connect: %d\n", errno);
    }

    skel->links.tcp_close = bpf_program__attach(skel->progs.tcp_close);
    if (!skel->links.tcp_close) {
        fprintf(stderr, "Failed to attach tcp_close: %d\n", errno);
    }

    skel->links.tcp_sendmsg = bpf_program__attach(skel->progs.tcp_sendmsg);
    if (!skel->links.tcp_sendmsg) {
        fprintf(stderr, "Failed to attach tcp_sendmsg: %d\n", errno);
    }

    skel->links.tracepoint_sys_enter_execve = bpf_program__attach(skel->progs.tracepoint_sys_enter_execve);
    if (!skel->links.tracepoint_sys_enter_execve) {
        fprintf(stderr, "Failed to attach execve tracepoint: %d\n", errno);
        err = -1;
        goto cleanup;
    }

    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_netspy), XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        goto cleanup;
    }

    print_pids_map(skel);

    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(struct perf_buffer_opts),
    };

    pb = perf_buffer__new(bpf_map__fd(skel->maps.output_map), 8, handle_event, handle_lost_events, NULL, &pb_opts);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        err = -1;
        goto cleanup;
    }

    // Устанавливаем обработчик сигналов
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("Monitoring network traffic on interface %s (index %d)\n", argv[1], ifindex);
    printf("Press Ctrl+C to stop\n");

    // Основной цикл обработки событий
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %d\n", err);
            break;
        }
        static time_t last_print = 0;
        time_t now = time(NULL);
        if (now - last_print >= 5) {
            print_pids_map(skel);
            print_connections_map(skel);
            last_print = now;
        }
    }

cleanup:
    // Очистка ресурсов
    if (pb) perf_buffer__free(pb);

    if (!exiting) {
        printf("\nFinal state of processes map:\n");
        print_pids_map(skel);
    }

    if (skel) {
        // Отсоединяем XDP программу
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        netspy_bpf__destroy(skel);
    }

    return err < 0 ? 1 : 0;
}

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    struct perf_trace_event *e = data;
    
    printf("Received event of size %u\n", size);
    if (size < sizeof(*e)) {
        fprintf(stderr, "Invalid event size: %u\n", size);
        return;
    }
    
    const char *type_str;
    switch (e->type) {
        case TYPE_ENTER: type_str = "ENTER"; break;
        case TYPE_DROP:  type_str = "DROP"; break;
        case TYPE_PASS:  type_str = "PASS"; break;
        default:         type_str = "UNKNOWN"; break;
    }
    
    printf("EVENT: type=%-6s timestamp=%-12llu processing_time=%-6uns\n",
           type_str, e->timestamp, e->processing_time_ns);

}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

static void print_pids_map(struct netspy_bpf *skel) {
    printf("\n=== Current Processes ===\n");
    printf("%-8s %s\n", "PID", "COMM");
    printf("------------------------\n");
    
    __u32 next_key = 0, key;
    char value[16];
    int map_fd = bpf_map__fd(skel->maps.pids);
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, value) == 0) {
            printf("%-8u %s\n", next_key, value);
        }
        key = next_key;
    }
    printf("========================\n\n");
}

static void print_connections_map(struct netspy_bpf *skel) {
    printf("\n=== Active Connections ===\n");
    printf("%-15s %-6s %-15s %-6s %-12s %-12s %-12s %s\n",
           "Source", "Port", "Dest", "Port", "Sent", "Received", "State", "Process");
    printf("----------------------------------------------------------------------------\n");
    
    struct connection_key key = {}, next_key;
    struct connection_info info;
    int map_fd = bpf_map__fd(skel->maps.connections);
    
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &info) == 0) {
            const char *state_str;
            switch (info.state) {
                case CONN_CLOSED: state_str = "CLOSED"; break;
                case CONN_ACTIVE: state_str = "ACTIVE"; break;
                case CONN_ESTABLISHED: state_str = "ESTAB"; break;
                default: state_str = "UNKNOWN"; break;
            }
            
            printf("%-15s %-6d %-15s %-6d %-12llu %-12llu %-12s %s(%d)\n",
                   inet_ntoa(*(struct in_addr*)&next_key.saddr), next_key.sport,
                   inet_ntoa(*(struct in_addr*)&next_key.daddr), next_key.dport,
                   info.bytes_sent, info.bytes_received,
                   state_str, info.process_comm, info.pid);
        }
        key = next_key;
    }
    printf("============================================================================\n\n");
}