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

static volatile bool exiting = false;

static void sig_handler(int sig) {
    exiting = true;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    return vfprintf(stderr, format, args);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
    // Обработка событий из perf buffer
    printf("Received event of size %u\n", size);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu events on CPU %d\n", lost_cnt, cpu);
}

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

    // Открываем и загружаем BPF программу
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

    // Присоединяем XDP программу к интерфейсу
    err = bpf_xdp_attach(ifindex, bpf_program__fd(skel->progs.xdp_dilih), XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
    if (err) {
        fprintf(stderr, "Failed to attach XDP program: %d\n", err);
        goto cleanup;
    }

    // Настраиваем perf buffer для получения событий
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
    }

cleanup:
    // Очистка ресурсов
    if (pb) perf_buffer__free(pb);
    
    if (skel) {
        // Отсоединяем XDP программу
        bpf_xdp_detach(ifindex, XDP_FLAGS_UPDATE_IF_NOEXIST, NULL);
        netspy_bpf__destroy(skel);
    }

    return err < 0 ? 1 : 0;
}