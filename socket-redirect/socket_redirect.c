// socket_redirect.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "socket_redirect.skel.h"

static volatile bool exiting = false;
static struct socket_redirect_bpf *skel = NULL;
static int cgroup_fd = -1;

void sig_handler(int sig) {
    exiting = true;
}

void cleanup(void) {
    if (cgroup_fd != -1) {
        bpf_prog_detach(cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE);
        close(cgroup_fd);
    }

    if (skel != NULL) {
        socket_redirect_bpf__destroy(skel);
    }
}

static int handle_perf_event(void *ctx, int cpu, void *data, __u32 data_sz) {
    struct connection_info *conn_info = data;

    printf("Connection: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
           conn_info->sip4 >> 24, (conn_info->sip4 >> 16) & 0xff, (conn_info->sip4 >> 8) & 0xff, conn_info->sip4 & 0xff,
           conn_info->sport,
           conn_info->dip4 >> 24, (conn_info->dip4 >> 16) & 0xff, (conn_info->dip4 >> 8) & 0xff, conn_info->dip4 & 0xff,
           conn_info->dport);

    return 0;
}

static void handle_perf_event_lost(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Lost %llu perf events on CPU %d\n", lost_cnt, cpu);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s /path/to/cgroup\n", argv[0]);
        return 1;
    }

    int err;

    signal(SIGINT, sig_handler);
    atexit(cleanup);

    skel = socket_redirect_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = socket_redirect_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }

    err = socket_redirect_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        return 1;
    }

    cgroup_fd = open(argv[1], O_DIRECTORY);
    if (cgroup_fd < 0) {
        perror("Failed to open cgroup");
        return 1;
    }

    // Use bpf_program__fd to get the file descriptor for sendmsg_prog
    err = bpf_prog_attach(bpf_program__fd(skel->progs.sendmsg_prog), cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE, 0);
    if (err) {
        perror("Failed to attach BPF program to cgroup");
        return 1;
    }

    // Set up perf buffer options
    struct perf_buffer_opts pb_opts = {
        .sample_cb = handle_perf_event,
        .lost_cb = handle_perf_event_lost,
    };

    // Set up the perf buffer
    struct perf_buffer *pb = perf_buffer__new(bpf_map__fd(skel->maps.perf_event_map), 16, &pb_opts);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    printf("Successfully attached BPF program to cgroup\n");

    while (!exiting) {
        perf_buffer__poll(pb, 100);
        sleep(1);
    }

    // Clean up the perf buffer
    perf_buffer__free(pb);

    return 0;
}
