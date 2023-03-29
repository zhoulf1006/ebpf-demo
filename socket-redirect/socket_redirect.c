// socket_redirect.c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <bpf/libbpf.h>

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

    err = bpf_prog_attach(skel->progs.handle_sock_addr, cgroup_fd, BPF_CGROUP_INET_SOCK_CREATE, 0);
    if (err) {
        perror("Failed to attach BPF program to cgroup");
        return 1;
    }

    printf("Successfully attached BPF program to cgroup\n");

    while (!exiting) {
        sleep(1);
    }

    return 0;
}
