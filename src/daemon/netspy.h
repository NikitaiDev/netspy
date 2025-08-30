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

static void sig_handler(int sig);
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
static void handle_event(void *ctx, int cpu, void *data, __u32 size);
static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt);