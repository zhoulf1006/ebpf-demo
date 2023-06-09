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
#include "socket_redirect.h"

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

// static int handle_ring_buffer_event(void *ctx, void *data, size_t len) {
//     struct connection_info *ci = (struct connection_info *)data;

//     printf("Socket: family=%d, src=%d.%d.%d.%d:%d, dst=%d.%d.%d.%d:%d\n",
//            ci->family,
//            ci->sip4 & 0xff, (ci->sip4 >> 8) & 0xff, (ci->sip4 >> 16) & 0xff, (ci->sip4 >> 24) & 0xff, ci->sport,
//            ci->dip4 & 0xff, (ci->dip4 >> 8) & 0xff, (ci->dip4 >> 16) & 0xff, (ci->dip4 >> 24) & 0xff, ci->dport);

//     return 0;
// }

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

    // Use bpf_program__fd to get the file descriptor for sendmsg_prog change BPF_CGROUP_INET_SOCK_CREATE -> BPF_SOCK_OPS
    err = bpf_prog_attach(bpf_program__fd(skel->progs.sendmsg_prog), cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE, 0);
    if (err) {
        perror("Failed to attach BPF program to cgroup");
        return 1;
    }

    // struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.ring_buffer_map),
    //                                            handle_ring_buffer_event, NULL, NULL);
    // if (!rb) {
    //     fprintf(stderr, "Failed to create ring buffer\n");
    //     return 1;
    // }

    printf("Successfully attached BPF program to cgroup\n");

    while (!exiting) {
        // int err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        // if (err < 0 && errno != EINTR) {
        //     fprintf(stderr, "Error polling ring buffer: %d\n", err);
        //     break;
        // }
        sleep(1);
    }

    // ring_buffer__free(rb);

    return 0;
}
