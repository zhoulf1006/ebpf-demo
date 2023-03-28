#include <linux/bpf.h>
#include <linux/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct bpf_map_def SEC("maps") sock_ops_map = {
    .type = BPF_MAP_TYPE_SOCKHASH,
    .key_size = sizeof(struct sock_key),
    .value_size = sizeof(int),
    .max_entries = 1024,
    .pinning = PIN_GLOBAL_NS,
};

struct sock_key {
    __u32 sip4;
    __u32 dip4;
    __u8  family;
    __u8  pad;
    __u16 dport;
    __u16 sport;
};

SEC("sockops")
int _sockops(struct bpf_sock_ops *skops) {
    struct sock_key key = {};
    int val = 0;

    key.sip4 = skops->local_ip4;
    key.dip4 = skops->remote_ip4;
    key.family = skops->family;
    key.dport = skops->remote_port;
    key.sport = skops->local_port;

    switch (skops->op) {
        case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
            bpf_sock_hash_update(skops, &sock_ops_map, &key, BPF_NOEXIST);
            break;
        default:
            break;
    }
    return 0;
}

SEC("cgroup/sendmsg")
int _sendmsg(struct bpf_sock_addr *ctx) {
    struct sock_key key = {};
    int *sock_idx;

    key.sip4 = ctx->user_ip4;
    key.dip4 = ctx->user_ip4;
    key.family = ctx->family;
    key.dport = ctx->user_port;
    key.sport = ctx->user_port;

    sock_idx = bpf_map_lookup_elem(&sock_ops_map, &key);
    if (sock_idx) {
        bpf_msg_redirect_hash(ctx, &sock_ops_map, &key, BPF_F_INGRESS);
        return SK_PASS;
    }

    return SK_DROP;
}

char _license[] SEC("license") = "GPL";
