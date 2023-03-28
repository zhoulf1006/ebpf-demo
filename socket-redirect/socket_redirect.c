#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include "socket_redirect.skel.h"

int main(int argc, char *argv[])
{
	struct socket_redirect_bpf *skel;
	int err;

	skel = socket_redirect_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF object\n");
		return 1;
	}

	err = socket_redirect_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF programs\n");
		goto cleanup;
	}

	printf("Socket redirect BPF program running\n");

	for (;;) {
		sleep(1);
	}

cleanup:
	socket_redirect_bpf__destroy(skel);
	return err != 0;
}
